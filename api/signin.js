import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import fs from 'fs';

export default async function handler(req, res) {
  if(req.method !== 'POST') return res.status(405).json({message:'Method not allowed'});
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({message:'Username & password required'});

  let users = [];
  try { users = JSON.parse(fs.readFileSync('./users.json')); } catch(e){}

  const user = users.find(u => u.username === username);
  if(!user) return res.status(400).json({message:'User not found'});

  const match = await bcrypt.compare(password, user.password);
  if(!match) return res.status(400).json({message:'Wrong password'});

  const token = jwt.sign({username}, 'YOUR_SECRET_KEY', {expiresIn:'1h'});
  res.status(200).json({token});
}
