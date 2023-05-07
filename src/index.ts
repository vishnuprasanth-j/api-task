import Express, { Request, Response,NextFunction } from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient,Token,Todo} from '@prisma/client';
import dotenv from 'dotenv';

interface User{
  id:number;
  name:string;
  email:string;
  password:string;
  todos?:Todo[];
  tokens?:Token[];
}

interface AuthRequest extends Request {
  user?: User;
}

dotenv.config()
const secret=process.env.JWT_SECRET||""
const prisma = new PrismaClient();
const app= Express()
app.use(Express.json());
app.use(cors());
const PORT:string=process.env.PORT||"6000"

app.get('/test',async(req,res)=>{
  res.json("hello")
})

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body

  try {
    const existingUser = await prisma.user.findUnique({
      where: {
        email: email,
      },
    })

    if (existingUser) {
      return res.status(409).json({ message: 'User with that email already exists' })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const newUser = await prisma.user.create({
      data: {
        name: name,
        email: email,
        password: hashedPassword,
      },
    })

    res.status(201).json({ message: 'User created successfully' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Server error' })
  }
})


app.post('/login', async (req, res) => {
  const { email, password } = req.body

  try {

    const user = await prisma.user.findUnique({
      where: {
        email: email,
      },
      include: {
        tokens: true,
      },
    })

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }


    const passwordMatch = await bcrypt.compare(password, user.password)

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' })
    }


    const token = jwt.sign({ userId: user.id }, secret)


    await prisma.token.create({
      data: {
        value: token,
        user: {
          connect: {
            id: user.id,
          },
        },
      },
    })

    res.json({ token })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Server error' })
  }
})


app.post('/logout', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1]

  try {

    const deletedToken = await prisma.token.delete({
      where: {
        value: token,
      },
    })

    if (!deletedToken) {
      return res.status(404).json({ message: 'Token not found' })
    }

    res.json({ message: 'Logout successful' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Server error' })
  }
})



const authMiddleware = async (req: AuthRequest, res: Response, next:NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1]

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' })
  }

  try {
    const decodedToken = jwt.verify(token, secret) as { userId: number }

    const user = await prisma.user.findUnique({
      where: {
        id: decodedToken.userId,
      },
      include: {
        tokens: {
          where: {
            value: token,
          },
        },
      },
    })

    if (!user || user.tokens.length === 0) {
      return res.status(401).json({ message: 'Invalid token' })
    }

    req.user = user

    next()
  } catch (error) {
    console.error(error)
    res.status(401).json({ message: 'Invalid token' })
  }
}


app.post('/todos', authMiddleware, async (req: AuthRequest, res: Response) => {
  const { title, completed } = req.body

  try {
    const newTodo = await prisma.todo.create({
      data: {
        title,
        completed,
        user: {
          connect: {
            id: req.user!.id,
          },
        },
      },
      include: {
        user: true,
      },
    })

    res.json(newTodo)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Server error' })
  }
})

app.get('/todos', authMiddleware, async (req: AuthRequest, res: Response) => {
  try {
    const todos = await prisma.todo.findMany({
      where: {
        userId: req.user!.id,
      },
    })

    res.json(todos)
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Server error' })
  }
})

app.put('/todos/:id', authMiddleware, async (req: AuthRequest, res) => {
  const id = Number(req.params.id)
  const { title, completed } = req.body

  try {
    const todo = await prisma.todo.findUnique({
      where: {
        id: id,
      },
    })

    if (!todo) {
      return res.status(404).json({ message: 'Todo not found' })
    }

    if (todo.userId !== req.user?.id) {
      return res.status(403).json({ message: 'Unauthorized' })
    }

    const updatedTodo = await prisma.todo.update({
      where: {
        id: id,
      },
      data: {
        title: title,
        completed: completed,
      },
    })

    res.json({ message: 'Todo updated successfully', data: updatedTodo })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Server error' })
  }
})


app.delete('/todos/:id', authMiddleware, async (req: AuthRequest, res) => {
  const id = Number(req.params.id)

  try {
    const todo = await prisma.todo.findUnique({
      where: {
        id: id,
      },
    })

    if (!todo) {
      return res.status(404).json({ message: 'Todo not found' })
    }

    if (todo.userId !== req.user?.id) {
      return res.status(403).json({ message: 'Unauthorized' })
    }

    await prisma.todo.delete({
      where: {
        id: id,
      },
    })

    res.json({ message: 'Todo deleted successfully' })
  } catch (error) {
    console.error(error)
    res.status(500).json({ message: 'Server error' })
  }
})



app.listen(PORT,()=>{console.log(PORT)})
