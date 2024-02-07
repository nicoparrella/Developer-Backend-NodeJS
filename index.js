const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const session = require('express-session');

const app = express();

// Conexión a MongoDB (asegúrate de tener MongoDB en ejecución)
mongoose.connect('mongodb://localhost:27017');

// Definir el esquema del usuario
const userSchema = new mongoose.Schema({
  nombre: String,
  apellido: String,
  usuario: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String,
});

const User = mongoose.model('User', userSchema);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret-key', resave: false, saveUninitialized: true }));

app.get('/registro', (req, res) => {
  res.sendFile(__dirname + '/registro.html');
});

app.post('/registro', async (req, res) => {
  const { nombre, apellido, usuario, email, password } = req.body;

  // Validaciones
  if (!nombre || !apellido || !usuario || !email || !password) {
    return res.send('Todos los campos son obligatorios');
  }

  // Verificar si el usuario o el correo ya existen
  const existingUser = await User.findOne({ $or: [{ usuario }, { email }] });
  if (existingUser) {
    return res.send
    (`
    <style>
      body {
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        text-align: center;
        padding: 20px;
      }
      p {
        color: #e53935;
        font-size: 18px;
        margin-bottom: 20px;
      }
      a {
        display: block;
        color: #e53935;
        text-decoration: none;
        font-size: 16px;
        padding: 10px;
        border: 1px solid #e53935;
        border-radius: 5px;
        transition: background-color 0.3s;
      }
      a:hover {
        background-color: #e53935;
        color: #fff;
      }
    </style>
    <p>Usuario o email ya registrados</p>
    <a href="/">Volver a la página principal</a>
  `);
  }

  // Encriptar la contraseña antes de almacenarla
  const hashedPassword = await bcrypt.hash(password, 10);

  // Crear nuevo usuario
  const newUser = new User({
    nombre,
    apellido,
    usuario,
    email,
    password: hashedPassword,
  });

  await newUser.save();
  res.send(`
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f4f4f4;
      text-align: center;
      padding: 20px;
    }
    p {
      color: #4caf50;
      font-size: 18px;
      margin-bottom: 20px;
    }
    a {
      display: block;
      color: #4caf50;
      text-decoration: none;
      font-size: 16px;
      padding: 10px;
      border: 1px solid #4caf50;
      border-radius: 5px;
      transition: background-color 0.3s;
    }
    a:hover {
      background-color: #4caf50;
      color: #fff;
    }
  </style>
  <p>Registro exitoso</p>
  <a href="/">Volver a la página principal</a>
`);
});

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

app.post('/login', async (req, res) => {
  const { usuario, password } = req.body;

  // Buscar el usuario en la base de datos
  const user = await User.findOne({ $or: [{ usuario }, { email: usuario }] });

  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.userId = user._id;
    res.send(`
    <style>
      body {
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        text-align: center;
        padding: 20px;
      }
      p {
        color: #4caf50;
        font-size: 18px;
        margin-bottom: 20px;
      }
      a {
        display: block;
        color: #4caf50;
        text-decoration: none;
        font-size: 16px;
        padding: 10px;
        border: 1px solid #4caf50;
        border-radius: 5px;
        transition: background-color 0.3s;
      }
      a:hover {
        background-color: #4caf50;
        color: #fff;
      }
    </style>
    <p>Inicio de sesión exitoso</p>
    <a href="/">Volver a la página principal</a>
  `);
  } else {
    res.send(`
    <style>
      body {
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        text-align: center;
        padding: 20px;
      }
      p {
        color: #e53935;
        font-size: 18px;
        margin-bottom: 20px;
      }
      a {
        display: block;
        color: #e53935;
        text-decoration: none;
        font-size: 16px;
        padding: 10px;
        border: 1px solid #e53935;
        border-radius: 5px;
        transition: background-color 0.3s;
      }
      a:hover {
        background-color: #e53935;
        color: #fff;
      }
    </style>
    <p>Usuario o contraseña incorrectos</p>
    <a href="/">Volver a la página principal</a>
  `);
  }
});

app.get('/modificar', (req, res) => {
  if (!req.session.userId) {
    return res.send(`
    <style>
      body {
        font-family: Arial, sans-serif;
        background-color: #f4f4f4;
        text-align: center;
        padding: 20px;
      }
      p {
        color: #e53935;
        font-size: 18px;
        margin-bottom: 20px;
      }
      a {
        display: block;
        color: #e53935;
        text-decoration: none;
        font-size: 16px;
        padding: 10px;
        border: 1px solid #e53935;
        border-radius: 5px;
        transition: background-color 0.3s;
      }
      a:hover {
        background-color: #e53935;
        color: #fff;
      }
    </style>
    <p>Acceso no autorizado. Debes iniciar sesión primero.</p>
    <a href="/">Volver a la página principal</a>
  `);
  }

  res.sendFile(__dirname + '/modificar.html');
});

app.post('/modificar', async (req, res) => {
  const userId = req.session.userId;
  const { nombre, apellido, usuario, email, password } = req.body;

  // Validaciones
  if (!nombre || !apellido || !usuario || !email || !password) {
    return res.send('Todos los campos son obligatorios');
  }

  // Actualizar la información del usuario
  await User.findByIdAndUpdate(userId, {
    nombre,
    apellido,
    usuario,
    email,
    password: await bcrypt.hash(password, 10),
  });

  res.send(`
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f4f4f4;
      text-align: center;
      padding: 20px;
    }
    p {
      color: #4caf50;
      font-size: 18px;
      margin-bottom: 20px;
    }
    a {
      display: block;
      color: #4caf50;
      text-decoration: none;
      font-size: 16px;
      padding: 10px;
      border: 1px solid #4caf50;
      border-radius: 5px;
      transition: background-color 0.3s;
    }
    a:hover {
      background-color: #4caf50;
      color: #fff;
    }
  </style>
  <p>Información actualizada correctamente</p>
  <a href="/">Volver a la página principal</a>
`);
});

app.get('/', (req, res) => {
  let sessionLinks = '';

  if (req.session.userId) {
    sessionLinks = `
      <li><a href="/modificar">Modificar Información</a></li>
      <li><a href="/logout">Cerrar Sesión</a></li>
    `;
  } else {
    sessionLinks = `
      <li><a href="/registro">Registro</a></li>
      <li><a href="/login">Iniciar Sesión</a></li>
    `;
  }

  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Página Principal</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          background-color: #f4f4f4;
          text-align: center;
          padding: 20px;
        }
        h1 {
          color: #333;
        }
        p {
          color: #555;
        }
        ul {
          list-style: none;
          padding: 0;
        }
        li {
          margin-bottom: 10px;
        }
        a {
          display: block;
          color: #4caf50;
          text-decoration: none;
          padding: 10px;
          border: 1px solid #4caf50;
          border-radius: 5px;
          transition: background-color 0.3s;
        }
        a:hover {
          background-color: #4caf50;
          color: #fff;
        }
      </style>
    </head>
    <body>
      <h1>Bienvenido a la página principal</h1>
      <p>Selecciona una opción:</p>
      <ul>
        ${sessionLinks}
      </ul>
    </body>
    </html>
  `);
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect('/');
    }
  });
});


// Iniciar el servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});

app.get('/api/v1/users', async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const count = parseInt(req.query.count) || 10;

  try {
    const users = await User.find()
      .skip((page - 1) * count)
      .limit(count);

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener la lista de usuarios' });
  }
});

app.get('/api/v1/users/:id', async (req, res) => {
  const userId = req.params.id;

  try {
    const user = await User.findById(userId);

    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ error: 'Usuario no encontrado' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener el usuario' });
  }
});

app.put('/api/v1/users/:id', async (req, res) => {
  const userId = req.params.id;
  const { nombre, apellido, usuario, email, password } = req.body;

  // Validaciones
  if (!nombre || !apellido || !usuario || !email || !password) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }

  try {
    const updatedUser = await User.findByIdAndUpdate(userId, {
      nombre,
      apellido,
      usuario,
      email,
      password: await bcrypt.hash(password, 10),
    });

    if (updatedUser) {
      res.json({ message: 'Usuario actualizado correctamente' });
    } else {
      res.status(404).json({ error: 'Usuario no encontrado' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar el usuario' });
  }
});

app.delete('/api/v1/users/:id', async (req, res) => {
  const userId = req.params.id;

  try {
    const deletedUser = await User.findByIdAndDelete(userId);

    if (deletedUser) {
      res.json({ message: 'Usuario eliminado correctamente' });
    } else {
      res.status(404).json({ error: 'Usuario no encontrado' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error al eliminar el usuario' });
  }
});

