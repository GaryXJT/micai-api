import { db } from "../db.js"
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import geoip from 'geoip-lite'



export const register = (req, res) => {
  const q = "SELECT * FROM user WHERE username=?"

  db.query(q, [req.body.username], (err, data) => {
    if (err) return res.json(err)
    if (!req.body.invitecode) return res.status(400).json('请联系管理员索要邀请码')
    if (!req.body.username || !req.body.password) return res.status(400).json('输入有误，请重新输入')
    if (data.length) return res.status(409).json('用户已存在，创建失败')
    const salt = bcrypt.genSaltSync(10)
    const hash = bcrypt.hashSync(req.body.password, salt)

    const q = "SELECT * FROM invitecode WHERE code=?"
    db.query(q, [req.body.invitecode], (err, data) => {
      if (err) return res.json(err)
      if (data.length == 0) return res.status(409).json('该邀请码无效')

      const q = "UPDATE invitecode SET state=?,activate_time=? WHERE code=?"
      const state = "used"
      const activate_time = new Date()
      db.query(q, [state, activate_time, req.body.invitecode], (err, data0) => {

        const q = "INSERT INTO user(`uuid`,`username`,`password`,`img`)VALUES(?)"
        const values = [
          req.body.uuid,
          req.body.username,
          hash,
          req.body.img,
        ]
        db.query(q, [values], (err, data) => {
          if (err) return res.json(err)

          const q = "SELECT id FROM user WHERE uuid=?"
          db.query(q, [req.body.uuid], (err, data0) => {
            const recordinputs = {
              operation: "Register新用户注册",
              resource_id: data0[0].id,
              region: "江苏 南京",
              user: '新用户',
              access: "普通用户",
              user_id: data0[0].id
            }
            return res.status(200).json(recordinputs)
          })
        })
      })
    })
  })
}

export const login = (req, res) => {
  const q = "SELECT * FROM user WHERE username=?"
  db.query(q, [req.body.username], (err, data) => {
    if (err) return res.json(req)
    if (data.length === 0) return res.status(404).json("用户不存在")

    //检查密码
    const isPasswordCorrect = bcrypt.compareSync(
      req.body.password,
      data[0].password
    )
    if (!isPasswordCorrect) return res.status(400).json("错误的用户名或密码")

    const token = jwt.sign({ id: data[0].id }, "jwtkey")
    const { password, ...other } = data[0]

    res.cookie("access_token", token, {
      httpOnly: true,
      expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 七天后过期
      sameSite: 'none',
      secure: true
    }).status(200).json(other)

  })

}

export const logout = (req, res) => {
  res.clearCookie("access_token", {
    sameSite: 'none',
    secure: true
  }).status(200).json("用户登出")
}

export const localStorage_remove = (req, res) => {
  const cookies = req.headers.cookie
  if (cookies && cookies.includes('access_token')) {
    return res.status(200).json(1)
  } else {
    return res.status(200).json(0)
  }
}