import express from "express"
import { register,login,logout,localStorage_remove } from "../controllers/auth.js"

const router=express.Router()

router.post('/register',register)
router.post('/login',login)
router.post('/logout',logout)
router.get('/localStorage_remove',localStorage_remove)

export default router