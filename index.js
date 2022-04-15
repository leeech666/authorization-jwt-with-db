const express = require('express');
const bodyParser = require("body-parser");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const SECRET = "fdfhfjdfdjfdjerwrereresaassa2dd@ddds"
const { User } = require('./model.js')


const app = express();

//app.use(express.json())
app.use(bodyParser.json());

app.use((req, res, next) => {
  console.log('Time: ',Date(Date.now()));
  next();
});

let POSTS = [
  {
    username: "Harsha",
    title: "Post 1",
    body: "1234"
  },
  {
    username: "Harsha",
    title: "Post 2",
    body: "1234"
  },
  {
    username: "Harsha",
    title: "Post 2",
    body: "1234"
  },
  {
    username: "Sm",
    title: "Post 2",
    body: "1234"
  },
  {
    username: "no",
    title: "Post 2",
    body: "1234"
  },
  {
    username: "cell",
    title: "Post 2",
    body: "1234"
  },
]

let DB = []

// used to store refresh tokens, as we will manually expire them
let SESSIONS = []

const generateAccessToken = (user) => {
  // jwt will make sure to expire this token in 30 seconds
  return jwt.sign(user, SECRET, {
    'expiresIn': '1h'
  })
}


// middlewares
const validateToken = async (token, tokenSecret) => {
  // returns user info, if the jwt token is valid
  return await jwt.verify(token, tokenSecret,
    (error, payload) => {
      if (error) {
        throw (error)
      }
      return payload
    })
}
const validateAccessToken = async (req, res, next) => {
  // returns user info, if the jwt token is valid
  try {
    req.user = await validateToken(req.body['accessToken'], SECRET)
    next();
  }
  catch (error) {
    res.status(401).
      json({ error: error.message || 'Invalid access token' })
  }
}

const validateRefreshToken = async (req, res, next) => {
  try {
    req.user = await validateToken(req.body['refreshToken'], SECRET)
    next();
  }
  catch (error) {
    res.status(401).
      json({ error: error.message || 'Invalid refresh token' })
  }
}

app.get('/', (req, res) => {
  res.send('Successful response.');
});


app.get("/posts", validateAccessToken, (req, res) => {
  const { username } = req.user;
  const userPosts = POSTS.filter((post) => post.username === username)
  res.json(userPosts)
  //res.json(POSTS);
})

app.post("/register", (req, res) => {
	console.log(req);
  const { username, password } = req.body;
  let hash = "";
  const salt =  bcrypt.genSaltSync(12);
  hash =  bcrypt.hashSync(password, salt);
  DB.push({ username, passwordHash: hash })
  console.log(DB);
  res.json("Successfully registered")
})

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  for (let user of DB) {
    // authentication
    if (user.username === username && await bcrypt.compare(password, user.passwordHash)) {
      // sending an accesstoken and refresh token in response
      // refresh token won't have expiration date and 
      // it will be used to generate new access token

      // We will store refresh token in db and it'll expire when the user logs out
      const accessToken = jwt.sign({ username: user.username }, SECRET, {
        'expiresIn': '30s'
      })
      const refreshToken = jwt.sign({ username: user.username }, SECRET)
      SESSIONS.push(refreshToken);
      res.json({ accessToken, refreshToken });
    }
  }
})

app.post('/token', validateRefreshToken, (req, res) => {
  // generating new access token, once the refresh token is valid and exists in db
  const { username } = req.user;
  if (SESSIONS.includes(req.body['refreshToken'])) {
    res.json({ accessToken: generateAccessToken({ username }) })
  }
  else {
    res.status(403).json('Forbidden: refresh token is expired')
  }
})

app.delete("/logout", async (req, res) => {
  // deleting refresh token from db 
  SESSIONS = SESSIONS.filter((session) => session != req.body['refreshToken']);
  res.sendStatus(204);
})


//************************
//************************
//using mongoDB
//************************

app.get('/api', (req, res) => res.send('Hello World!'))

// 从MongoDB数据库express-auth中的User表查询所有的用户信息
app.get('/api/users', async(req, res) => {
  const users = await User.find()
  res.send(users)
})

app.post('/api/register', async (req, res) => {
  // console.log(req.body)
  // 在MongoDB数据库表USer中新增一个用户
  const user = await User.create({
    username: req.body.username,
    password: req.body.password,
  })

  // res.send('register')
  res.send(user)
})

app.post('/api/login', async (req, res) => {
  // res.send('login')
  // 1.看用户是否存在
  const user = await User.findOne({
    username: req.body.username
  })
  if (!user) {
    return res.status(422).send({
      message: '用户名不存在'
    })
  }
  // 2.用户如果存在，则看密码是否正确
  const isPasswordValid = bcrypt.compareSync(
    req.body.password,
    user.password
    )
    if(!isPasswordValid) {
      // 密码无效
      return res.status(422).send({
        message: '密码无效'
      })
    }
  // 生成token
  const token = jwt.sign({
    id: String(user._id),
  }, SECRET)

  res.send({
    user,
    token
  })
})

// 中间件：验证授权
const auth = async (req, res, next) => {
   // 获取客户端请求头的token
   //const rawToken = String(req.headers.authorization).split(' ').pop()
   const rawToken = req.body['token'];
   const tokenData = jwt.verify(rawToken, SECRET);
  //  console.log(tokenData)
   // 获取用户id
   const id = tokenData.id;
  //  const user = await User.findById(id)
  req.user = await User.findById(id);
  next()
}

app.get('/api/profile', auth, async (req, res) => {
  res.send(req.user)
})

app.listen(3000, () => console.log('Example app is listening on port 3000.'));
