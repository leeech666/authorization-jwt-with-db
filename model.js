/* jshint esversion: 8 */ 
const mongoose = require('mongoose')

// const bcrypt = require('bcrypt')
// const saltRounds = 10

// const bcrypt = require('bcryptjs')

mongoose.connect('mongodb://localhost:27017/express-auth', {
  useNewUrlParser:true,
  useUnifiedTopology: true,
  //useCreateIndex: true
})

const bcrypt = require('bcryptjs')

// 定义一个用户模型，username是唯一的索引，表示不能被重复
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: { 
    type: String, 
    set(val) {
      // var hash = bcrypt.hashSync(val, saltRounds)
      // return require('bcrypt').hashSync(val, 10)
      var salt = bcrypt.genSaltSync(10)
      var hash = bcrypt.hashSync(val, salt)
      return hash
    }
  },
})

// create the model for users and expose it to our app
const User = mongoose.model('User', UserSchema)

// 删除用户集合
// User.db.dropCollection('users')

module.exports = { User }