const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const express = require('express')
const session = require('cookie-session')
const bodyParser = require('body-parser')
const multer = require('multer')
const mysql = require('mysql')
const ECT = require('ect')
const promisify = require('es6-promisify')

const STATIC_FOLDER = path.join(__dirname, '..', 'public')
const ICONS_FOLDER = path.join(STATIC_FOLDER, 'icons')
const AVATAR_MAX_SIZE = 1 * 1024 * 1024
const PORT = 5000
const ICON_FILE_NAMES = require('./icon_file_names')

const ect = new ECT({
  root: path.join(__dirname, 'views'),
  ext : '.html',
})
const upload = multer({ dest: '/tmp' })
const app = express()

app.set('view engine', 'html')
app.engine('html', ect.render)
app.use(express.static(STATIC_FOLDER))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(session({
  name: 'session',
  keys: ['tonymoris'],
  maxAge: 360000,
}))
app.use((err, req, res, next) => {
  res.status(500).end()
})

function now() {
  return new Date().toString();
}

const usersCache = [];
const channelCache = {};

function cacheUser(user) {
  usersCache.push(user);
}

function findUserByName(name) {
  return usersCache.find((user) => user.name === name);
}

function findUserById(id) {
  return usersCache.find((user) => user.id === id);  
}

function updateUserAvatarIcon(userId, avatarIcon) {
  const user = findUserById(userId);
  user.avatar_icon = avatarIcon;
}

function updateUserDisplayName(userId, displayName) {
  const user = findUserById(userId);
  user.display_name = displayName;
}

function cacheChannel(id, channel) {
  channelCache[id] = channel;
}

function findChannelById(id) {
  return channelCache[id];
}

function addMessage(channelId, userId, content) {
  const channel = findChannelById(channelId);
  const user = findUserById(userId);
  const messageId = `message_${getSequence()}`;
  channel.messages.push({
    id: messageId,
    display_name: user.display_name,
    avatar_icon: user.avatar_icon,
    created_at: now(),
    content: content
  });

  if (user.messages[channel.id] == null) {
    user.messages[channel.id] = [];
  }

  const channelIds = user.messages[channel.id];
  channelIds.push(messageId); 
}

const seq = (() => {
    var seq = 0;
    return () => {
        return seq++
    }
})();

function getSequence() {
  return seq();
}


const pool = mysql.createPool({
  connectionLimit: 20,
  socketPath: '/var/run/mysqld/mysqld.sock',
  user: 'isucon', //process.env.ISUBATA_DB_USER || 'root',
  password: 'isucon',
  database: 'isubata',
  charset: 'utf8mb4',
})
pool.query = promisify(pool.query, pool)


const getInitialize = async (req, res) => {
    await pool.query('DELETE FROM user WHERE id > 1000');
    await pool.query('DELETE FROM image WHERE id > 1001');
    await pool.query('DELETE FROM channel WHERE id > 10');
    await pool.query('DELETE FROM message WHERE id > 10000');
    await pool.query('DELETE FROM haveread');

    const channels = await pool.query('select id, name, description, created_at, updated_at from channel');

    for (let c of channels) {
        const channelId = c.id;
        const messages = await pool.query('select m.id, u.display_name, u.avatar_icon, m.content, m.created_at from message as m inner join user as u on m.user_id = u.id where m.channel_id = ? order by m.id desc', [channelId]);

        channelCache[channelId] = {
            id: channelId,
            name: c.name,
            description: c.description,
            created_at: c.created_at,
            updated_at: c.updated_at,
            messages: messages
        }
    }

    const users = await pool.query('select id, name, salt, password, display_name, created_at from user;');
    for (let u of users) {
        u.messages = {};
        const userId = u.id;
        const messages = await pool.query('select m.channel_id, m.id from message as m where m.user_id = ?', [userId]);
        console.log(`userId: ${userId}, messages: ${messages.length}`)
        for (let m of messages) {
            const channelId = m.channel_id;
            const messageId = m.id;
            console.log(userId, channelId, messageId);
            if (!u.messages[channelId]) {
                u.messages[channelId] = [messageId];
            } else {
                u.messages[channelId].push(messageId)
            }
        }
        usersCache.push(u);
    }
    channelCache
    console.log(`cachedChannels: ${Object.keys(channelCache)}`);
    console.log(`cachedUsers: ${usersCache.length}`);
    return res.status(204).send('');
}
app.get('/initialize', getInitialize)


function dbGetUser(conn, userId) {
  return conn.query('SELECT id, name, display_name FROM user WHERE id = ?', [userId])
    .then(([result]) => result)
}

function dbAddMessage(conn, channelId, userId, content) {
  return conn.query('INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())', [channelId, userId, content])
}

function loginRequired(req, res, next) {
  if (!req.session.userId) {
    res.redirect(303, '/login')
    return
  }

  req.userId = req.session.userId
  const user = findUserById(req.userId);
  req.user = user
  next();
  
  // return dbGetUser(pool, req.userId)
  //   .then(user => {
  //     req.user = user
  //     next()
  //   })
}

function randomString(len) {
  const seed = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
  let str = ''
  while (--len) {
    str += seed[~~(Math.random() * seed.length)]
  }
  return str
}

function register(conn, user, password) {
  const salt = randomString(20)
  const passDigest = crypto.createHash('sha1')
    .update(salt + password)
    .digest('hex')

  return conn.query(`INSERT INTO user (name, salt, password, display_name, avatar_icon, created_at)
    VALUES (?, ?, ?, ?, ?, NOW())`,
    [user, salt, passDigest, user, 'default.png'])
    .then(({ insertId }) => insertId)
}

function register2(name, password) {
  const salt = randomString(20)
  const passDigest = crypto.createHash('sha1')
    .update(salt + password)
    .digest('hex')

  const userId = getSequence();
  cacheUser({
    id: userId,
    name: name,
    salt: salt,
    password: passDigest,
    display_name: name,
    avatar_icon: 'default.png',
    created_at: new Date().toString(),
    messages: {},
    haveread: {}
  });

  return userId;
}

app.get('/', getIndex)
function getIndex(req, res) {
  if (req.session.userId) {
    res.redirect(303, '/channel/1')
  } else {
    res.render('index', { req })
  }
}

function getChannelListInfo (conn, focusChannelId = null) {
  return conn.query('SELECT id, name FROM channel ORDER BY id')
    .then(channels => {
      let description = ''
      channels.forEach((channel) => {
        if (channel.id == focusChannelId) {
          description = channel.description
        }
      })

      return { channels, description }
    })
}

app.get('/channel/:channelId', loginRequired, getChannel)
function getChannel(req, res) {
  const { channelId } = req.params
  return getChannelListInfo(pool, channelId)
    .then(({ channels, description }) => {
      res.render('channel', {
        req,
        channels,
        description,
        channelId,
      })
    })
}

app.get('/register', getRegister)
function getRegister(req, res) {
  res.render('register', { req })
}

app.post('/register', postRegister)
function postRegister(req, res) {
  const { name, password } = req.body
  if (!name || !password) {
    res.status(400).end()
    return
  }

  const userId = register2(name, password);
  req.session.userId = userId;
  res.redirect(303, '/');

  // return register(pool, name, password)
  //   .then(userId => {
  //     req.session.userId = userId
  //     res.redirect(303, '/')
  //   })
  //   .catch(e => {
  //     res.status(409).end()
  //   })
}

app.get('/login', getLogin)
function getLogin(req, res) {
  res.render('login', { req })
}

app.post('/login', postLogin)
function postLogin(req, res) {

  const user = findUserByName(req.body.name);
  
  if (!user) {
    res.status(403).end()
    return
  }

  const { salt, password, id } = user
  const shasum = crypto.createHash('sha1')
  shasum.update(salt + req.body.password)
  const digest = shasum.digest('hex')
  if (password === digest) {
    req.session.userId = id
    res.redirect(303, '/')
  } else {
    res.status(403).end()
  }
    
  // return pool.query('SELECT salt, password, id FROM user WHERE name = ?', [req.body.name])
  //   .then(([row]) => {
  //     if (!row) {
  //       res.status(403).end()
  //       return
  //     }

  //     const { salt, password, id } = row
  //     const shasum = crypto.createHash('sha1')
  //     shasum.update(salt + req.body.password)
  //     const digest = shasum.digest('hex')
  //     if (password === digest) {
  //       req.session.userId = id
  //       res.redirect(303, '/')
  //     } else {
  //       res.status(403).end()
  //     }
  //   })
}

app.get('/logout', getLogout)
function getLogout(req, res) {
  req.session = null
  res.redirect(303, '/')
}

app.post('/message', postMessage)
function postMessage(req, res) {
  const { userId } = req.session

  const user = findUserById(userId);

  const { channel_id, message } = req.body
  if (!user || !channel_id || !message) {
    res.status(403).end()
    return
  }

  addMessage(channel_id, userId, message);
  res.status(204).end('');

  // return dbAddMessage(pool, channel_id, userId, message)
  //   .then(() => res.status(204).end(''))
  // return dbGetUser(pool, userId)
  //   .then(user => {
  //     const { channel_id, message } = req.body
  //     if (!user || !channel_id || !message) {
  //       res.status(403).end()
  //       return
  //     }

  //     return dbAddMessage(pool, channel_id, userId, message)
  //       .then(() => res.status(204).end(''))
  //   })
}

function zeroPadd (num, digit) {
  return ('0'.repeat(digit) + num).slice(-digit)
}

function formatDate (dateStr) {
  const d = new Date(dateStr)
  const datePart = [d.getFullYear(), zeroPadd(d.getMonth() + 1, 2), zeroPadd(d.getDate(), 2)].join('/')
  const timePart = [zeroPadd(d.getHours(), 2), zeroPadd(d.getMinutes(), 2), zeroPadd(d.getSeconds(), 2)].join(':')
  return datePart + ' ' + timePart
}

app.get('/message', getMessage)
function getMessage(req, res) {
  const { userId } = req.session
  if (!userId) {
    res.status(403).end()
    return
  }

  const { channel_id, last_message_id } = req.query
  return pool.query('SELECT id, user_id, content, created_at FROM message WHERE id > ? AND channel_id = ? ORDER BY id DESC LIMIT 100', [last_message_id, channel_id])
    .then(rows => {
      const response = []
      let p = Promise.resolve()
      rows.forEach((row, i) => {
        const r = {}
        r.id = row.id
        p = p.then(() => {
          return pool.query('SELECT name, display_name, avatar_icon FROM user WHERE id = ?', [row.user_id])
            .then(([user]) => {
              r.user = user
              r.date = formatDate(row.created_at)
              r.content = row.content
              response[i] = r
            })
        })
      })

      return p.then(() => {
        response.reverse()
        const maxMessageId = rows.length ? Math.max(...rows.map(r => r.id)) : 0
        return pool.query(`INSERT INTO haveread (user_id, channel_id, message_id, updated_at, created_at)
          VALUES (?, ?, ?, NOW(), NOW())
          ON DUPLICATE KEY UPDATE message_id = ?, updated_at = NOW()`,
          [userId, channel_id, maxMessageId, maxMessageId])
          .then(() => res.json(response))
      })
    })
}

function sleep (seconds) {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve()
    }, seconds * 1000)
  })
}

app.get('/fetch', fetchUnread)
function fetchUnread(req, res) {
  const { userId } = req.session
  if (!userId) {
    res.status(403).end()
    return
  }

  return sleep(1.0)
    .then(() => pool.query('SELECT id FROM channel'))
    .then(rows => {
      const channelIds = rows.map(row => row.id)
      const results = []
      let p = Promise.resolve()

      channelIds.forEach(channelId => {
        p = p.then(() => pool.query('SELECT message_id FROM haveread WHERE user_id = ? AND channel_id = ?', [userId, channelId]))
          .then(([row]) => {
            if (row) {
              return pool.query('SELECT COUNT(id) as cnt FROM message WHERE channel_id = ? AND ? < id', [channelId, row.message_id])
            } else {
              return pool.query('SELECT COUNT(id) as cnt FROM message WHERE channel_id = ?', [channelId])
            }
          })
          .then(([row3]) => {
            const r = {}
            r.channel_id = channelId
            r.unread = row3.cnt
            results.push(r)
          })
      })

      return p.then(() => results)
    })
    .then(results => res.json(results))
}

app.get('/history/:channelId', loginRequired, getHistory)
function getHistory(req, res) {
  const { channelId } = req.params
  let page = parseInt(req.query.page || '1')

  const N = 20
  return pool.query('SELECT COUNT(id) as cnt FROM message WHERE channel_id = ?', [channelId])
    .then(([row2]) => {
      const cnt = row2.cnt
      const maxPage = Math.max(Math.ceil(cnt / N), 1)

      if (isNaN(page) || page < 1 || page > maxPage) {
        res.status(400).end()
        return
      }

      return pool.query('SELECT id, user_id, content, created_at FROM message WHERE channel_id = ? ORDER BY id DESC LIMIT ? OFFSET ?', [channelId, N, (page - 1) * N])
        .then(rows => {
          const messages = []
          let p = Promise.resolve()
          rows.forEach(row => {
            const r = {}
            r.id = row.id
            p = p.then(() => {
              return pool.query('SELECT name, display_name, avatar_icon FROM user WHERE id = ?', [row.user_id])
                .then(([user]) => {
                  r.user = user
                  r.date = formatDate(row.created_at)
                  r.content = row.content
                  messages.push(r)
                })
            })
          })

          return p.then(() => {
            messages.reverse()
            return getChannelListInfo(pool, channelId)
              .then(({ channels, description }) => {
                res.render('history', {
                  req, channels, channelId, messages, maxPage, page,
                })
              })
          })
      })
    })
}

app.get('/profile/:userName', loginRequired, getProfile)
function getProfile(req, res) {
  const { userName } = req.params
  return getChannelListInfo(pool)
    .then(({ channels }) => {
      return pool.query('SELECT id, name, display_name, avatar_icon FROM user WHERE name = ?', [userName])
        .then(([user]) => {
          if (!user) {
            res.status(404).end()
            return
          }

          const selfProfile = req.user.id == user.id
          return res.render('profile', { req, channels, user, selfProfile })
        })
    })
}

app.get('/add_channel', loginRequired, getAddChannel)
function getAddChannel(req, res) {
  return getChannelListInfo(pool)
    .then(({ channels }) => {
      res.render('add_channel', { req, channels })
    })
}

app.post('/add_channel', loginRequired, postAddChannel)
function postAddChannel(req, res) {
  const { name, description } = req.body
  if (!name || !description) {
    res.status(400).end()
    return
  }

  const id = getSequence();

  cacheChannel(id, {
    id: id,
    name: name,
    description: description,
    created_at: now(),
    updated_at: now(),
    messages: []
  });
  res.redirect(303, '/channel/' + id);

  // return pool.query('INSERT INTO channel (name, description, updated_at, created_at) VALUES (?, ?, NOW(), NOW())', [name, description])
  //   .then(({ insertId }) => {
  //     res.redirect(303, '/channel/' + insertId)
  //   })
}

app.post('/profile', loginRequired, upload.single('avatar_icon'), postProfile)
function postProfile(req, res) {
  const { userId } = req.session
  if (!userId) {
    res.status(403).end()
    return
  }

  const user = findUserById(userId);

  if (!user) {
    res.status(403).end()
    return
  }

  const { display_name } = req.body
  const avatar_icon = req.file
  let avatarName, avatarData

  // let p = Promise.resolve()
  if (avatar_icon) {
    if (avatar_icon.originalname) {
      const ext = path.extname(avatar_icon.originalname) || ''
      if (!['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) {
        res.status(400).end()
        return
      }

      if (avatar_icon.size > AVATAR_MAX_SIZE) {
        res.status(400).end()
        return
      }

      const data = fs.readFileSync(avatar_icon.path)
      const shasum = crypto.createHash('sha1')
      shasum.update(data)
      const digest = shasum.digest('hex')

      avatarName = digest + (ext ? `.${ext}` : '')
      avatarData = data
    }
  }
  if (avatarName && avatarData) {

    if (!ICON_FILE_NAMES.includes(avatarName)) {
      fs.createReadStream(avatar_icon.path).pipe(fs.createWriteStream('/home/isucon/isubata/webapp/public/icons/' + avatarName));
    }
    updateUserAvatarIcon(userId, avatar_icon);
    // p = p.then(() => pool.query('UPDATE user SET avatar_icon = ? WHERE id = ?', [avatarName, userId]))
  }

  if (display_name) {
    updateUserDisplayName(userId, display_name);
  }

  res.redirect(303, '/');
  // return dbGetUser(pool, userId)
  //   .then(user => {
  //     if (!user) {
  //       res.status(403).end()
  //       return
  //     }

  //     const { display_name } = req.body
  //     const avatar_icon = req.file
  //     let avatarName, avatarData

  //     let p = Promise.resolve()
  //     if (avatar_icon) {
  //       if (avatar_icon.originalname) {
  //         const ext = path.extname(avatar_icon.originalname) || ''
  //         if (!['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) {
  //           res.status(400).end()
  //           return
  //         }

  //         if (avatar_icon.size > AVATAR_MAX_SIZE) {
  //           res.status(400).end()
  //           return
  //         }

  //         const data = fs.readFileSync(avatar_icon.path)
  //         const shasum = crypto.createHash('sha1')
  //         shasum.update(data)
  //         const digest = shasum.digest('hex')

  //         avatarName = digest + (ext ? `.${ext}` : '')
  //         avatarData = data
  //       }
  //     }
  //     if (avatarName && avatarData) {

  //       if (!ICON_FILE_NAMES.includes(avatarName)) {
  //         fs.createReadStream(avatar_icon.path).pipe(fs.createWriteStream('/home/isucon/isubata/webapp/public/icons/' + avatarName));
  //       }
  //       p = p.then(() => pool.query('UPDATE user SET avatar_icon = ? WHERE id = ?', [avatarName, userId]))
  //     }

  //     if (display_name) {
  //       p = p.then(() => pool.query('UPDATE user SET display_name = ? WHERE id = ?', [display_name, userId]))
  //     }

  //     return p.then(() => res.redirect(303, '/'))
  //   })
}

function ext2mime(ext) {
  switch(ext) {
    case '.jpg':
    case '.jpeg':
      return 'image/jpeg'
    case '.png':
      return 'image/png'
    case '.gif':
      return 'image/gif'
    default:
      return ''
  }
}

app.get('/icons/:fileName', getIcon)
function getIcon(req, res) {
  const { fileName } = req.params
  return pool.query('SELECT * FROM image WHERE name = ?', [fileName])
    .then(([row]) => {
      const ext = path.extname(fileName) || ''
      const mime = ext2mime(ext)
      if (!row || !mime) {
        res.status(404).end()
        return
      }
      res.header({ 'Content-Type': mime }).end(row.data)
    })
}

app.listen(PORT, () => {
  console.log('Example app listening on port ' + PORT + '!')
})
