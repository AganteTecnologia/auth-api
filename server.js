// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const User = require('./models/User');

const app = express();
app.use(express.json());

// Conexão ao MongoDB
mongoose.connect(process.env.MONGODB_URI).then(() => console.log("Conectado ao MongoDB"))
  .catch((err) => console.log("Erro ao conectar ao MongoDB:", err));

// Função para gerar tokens JWT
function generateToken(user) {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

// Rota para registro de usuário
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = new User({ email, password });
    await user.save();
    res.status(201).json({ message: 'Usuário registrado com sucesso' });
  } catch (error) {
    res.status(400).json({ error: 'Erro ao registrar o usuário' });
  }
});

// Endpoint para login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const user = await User.findOne({ username: email });
      if (!user) return res.status(401).json({ success: false, message: 'Usuário não encontrado' });
  
      const isMatch = await user.comparePassword(password);
      if (!isMatch) return res.status(401).json({ success: false, message: 'Senha incorreta' });
  
      res.json({ success: true, message: 'Login bem-sucedido' });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Erro no servidor' });
    }
  });

// Rota protegida (apenas para teste)
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Conteúdo protegido acessado com sucesso' });
});

// Middleware para verificar o token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(403).json({ error: 'Token não fornecido' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Token inválido' });
    req.userId = decoded.id;
    next();
  });
}

// Inicia o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
