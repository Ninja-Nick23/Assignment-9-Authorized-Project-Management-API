const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, User, Project, Task } = require('./database/setup');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

/* ============================
   JWT AUTH MIDDLEWARE
============================ */

function requireAuth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'Missing Authorization header' });

    const token = header.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Missing token' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // attach user info
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

function requireManager(req, res, next) {
    if (req.user.role === 'manager' || req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ error: 'Managers only' });
}

function requireAdmin(req, res, next) {
    if (req.user.role === 'admin') {
        return next();
    }
    return res.status(403).json({ error: 'Admins only' });
}

/* ============================
   TEST DB CONNECTION
============================ */

async function testConnection() {
    try {
        await db.authenticate();
        console.log('Connection to database established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}

testConnection();

/* ============================
   AUTH ROUTES
============================ */

// REGISTER
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, role = 'employee' } = req.body;

        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) return res.status(400).json({ error: 'Email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = await User.create({
            name,
            email,
            password: hashedPassword,
            role
        });

        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// LOGIN (JWT)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ where: { email } });
        if (!user) return res.status(401).json({ error: 'Invalid email or password' });

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) return res.status(401).json({ error: 'Invalid email or password' });

        const token = jwt.sign(
            {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRES_IN }
        );

        res.json({
            message: 'Login successful',
            token
        });

    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// LOGOUT (JWT is stateless)
app.post('/api/logout', (req, res) => {
    res.json({ message: 'Logout successful (JWT requires no server cleanup)' });
});

/* ============================
   USER ROUTES
============================ */

app.get('/api/users/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, {
            attributes: ['id', 'name', 'email', 'role']
        });

        if (!user) return res.status(404).json({ error: 'User not found' });

        res.json(user);
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// ADMIN ONLY
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const users = await User.findAll({
            attributes: ['id', 'name', 'email', 'role']
        });

        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

/* ============================
   PROJECT ROUTES
============================ */

app.get('/api/projects', requireAuth, async (req, res) => {
    try {
        const projects = await Project.findAll({
            include: [
                { model: User, as: 'manager', attributes: ['id', 'name', 'email'] }
            ]
        });

        res.json(projects);
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});

app.get('/api/projects/:id', requireAuth, async (req, res) => {
    try {
        const project = await Project.findByPk(req.params.id, {
            include: [
                { model: User, as: 'manager', attributes: ['id', 'name', 'email'] },
                {
                    model: Task,
                    include: [
                        { model: User, as: 'assignedUser', attributes: ['id', 'name', 'email'] }
                    ]
                }
            ]
        });

        if (!project) return res.status(404).json({ error: 'Project not found' });

        res.json(project);
    } catch (error) {
        console.error('Error fetching project:', error);
        res.status(500).json({ error: 'Failed to fetch project' });
    }
});

// MANAGER+
app.post('/api/projects', requireAuth, requireManager, async (req, res) => {
    try {
        const { name, description, status = 'active' } = req.body;

        const newProject = await Project.create({
            name,
            description,
            status,
            managerId: req.user.id
        });

        res.status(201).json(newProject);
    } catch (error) {
        console.error('Error creating project:', error);
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// MANAGER+
app.put('/api/projects/:id', requireAuth, requireManager, async (req, res) => {
    try {
        const { name, description, status } = req.body;

        const [updated] = await Project.update(
            { name, description, status },
            { where: { id: req.params.id } }
        );

        if (!updated) return res.status(404).json({ error: 'Project not found' });

        const updatedProject = await Project.findByPk(req.params.id);
        res.json(updatedProject);
    } catch (error) {
        console.error('Error updating project:', error);
        res.status(500).json({ error: 'Failed to update project' });
    }
});

// ADMIN ONLY
app.delete('/api/projects/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const deleted = await Project.destroy({ where: { id: req.params.id } });

        if (!deleted) return res.status(404).json({ error: 'Project not found' });

        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Error deleting project:', error);
        res.status(500).json({ error: 'Failed to delete project' });
    }
});

/* ============================
   TASK ROUTES
============================ */

app.get('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    try {
        const tasks = await Task.findAll({
            where: { projectId: req.params.id },
            include: [
                { model: User, as: 'assignedUser', attributes: ['id', 'name', 'email'] }
            ]
        });

        res.json(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

// MANAGER+
app.post('/api/projects/:id/tasks', requireAuth, requireManager, async (req, res) => {
    try {
        const { title, description, assignedUserId, priority = 'medium' } = req.body;

        const newTask = await Task.create({
            title,
            description,
            projectId: req.params.id,
            assignedUserId,
            priority,
            status: 'pending'
        });

        res.status(201).json(newTask);
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

// MANAGER+
app.delete('/api/tasks/:id', requireAuth, requireManager, async (req, res) => {
    try {
        const deleted = await Task.destroy({ where: { id: req.params.id } });

        if (!deleted) return res.status(404).json({ error: 'Task not found' });

        res.json({ message: 'Task deleted successfully' });
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

/* ============================
   START SERVER
============================ */

app.listen(PORT, () => {
    console.log(`Server running on port http://localhost:${PORT}`);
});
