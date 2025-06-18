const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const compression = require('compression');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./config/database');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'lds-scripture-search-jwt-secret-key';

// Middleware
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    message: 'LDS Scripture Search API is running!'
  });
});

// Get all books organized by testament
app.get('/api/books', async (req, res) => {
  try {
    await db.connect();
    
    const books = await db.all(`
      SELECT DISTINCT name, testament, book_order 
      FROM books 
      ORDER BY 
        CASE testament 
          WHEN 'Old Testament' THEN 1
          WHEN 'New Testament' THEN 2
          WHEN 'Book of Mormon' THEN 3
          WHEN 'Doctrine and Covenants' THEN 4
          WHEN 'Pearl of Great Price' THEN 5
          ELSE 6
        END,
        book_order
    `);
    
    // Group books by testament
    const booksByTestament = books.reduce((acc, book) => {
      if (!acc[book.testament]) {
        acc[book.testament] = [];
      }
      acc[book.testament].push(book.name);
      return acc;
    }, {});
    
    await db.close();
    res.json({ books: booksByTestament });
  } catch (error) {
    console.error('Error fetching books:', error);
    await db.close();
    res.status(500).json({ error: 'Failed to fetch books' });
  }
});

// User registration
app.post('/api/users/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    await db.connect();

    // Check if user already exists
    const existingUser = await db.get(
      'SELECT id FROM users WHERE username = ? OR email = ?',
      [username, email]
    );

    if (existingUser) {
      await db.close();
      return res.status(409).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const result = await db.run(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, passwordHash]
    );

    // Generate JWT token
    const token = jwt.sign(
      { userId: result.id, username, email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    await db.close();

    res.status(201).json({
      message: 'User created successfully',
      user: {
        id: result.id,
        username,
        email
      },
      token
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed', message: error.message });
  }
});

// User login
app.post('/api/users/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    await db.connect();

    // Find user by username or email
    const user = await db.get(
      'SELECT id, username, email, password_hash, is_active FROM users WHERE username = ? OR email = ?',
      [username, username]
    );

    if (!user) {
      await db.close();
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.is_active) {
      await db.close();
      return res.status(401).json({ error: 'Account is deactivated' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);

    if (!isValidPassword) {
      await db.close();
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last login
    await db.run(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
      [user.id]
    );

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    await db.close();

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      },
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed', message: error.message });
  }
});

// Get user bookmarks
app.get('/api/bookmarks', authenticateToken, async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;

    await db.connect();

    const bookmarks = await db.all(`
      SELECT 
        bm.id,
        bm.note,
        bm.tags,
        bm.created_at,
        v.id as verse_id,
        v.chapter,
        v.verse,
        v.text,
        b.name as book_name,
        b.abbreviation as book_abbrev,
        b.testament,
        (b.name || ' ' || v.chapter || ':' || v.verse) as reference
      FROM bookmarks bm
      JOIN verses v ON bm.verse_id = v.id
      JOIN books b ON v.book_id = b.id
      WHERE bm.user_id = ?
      ORDER BY bm.created_at DESC
      LIMIT ? OFFSET ?
    `, [req.user.userId, limit, offset]);

    await db.close();

    res.json({
      bookmarks: bookmarks.map(bm => ({
        id: bm.id,
        note: bm.note,
        tags: bm.tags ? bm.tags.split(',').map(tag => tag.trim()) : [],
        createdAt: bm.created_at,
        verse: {
          id: bm.verse_id,
          reference: bm.reference,
          book: bm.book_name,
          abbreviation: bm.book_abbrev,
          testament: bm.testament,
          chapter: bm.chapter,
          verse: bm.verse,
          text: bm.text
        }
      }))
    });

  } catch (error) {
    console.error('Get bookmarks error:', error);
    res.status(500).json({ error: 'Failed to fetch bookmarks', message: error.message });
  }
});

// Add bookmark
app.post('/api/bookmarks', authenticateToken, async (req, res) => {
  try {
    const { verseId, note, tags } = req.body;

    if (!verseId) {
      return res.status(400).json({ error: 'Verse ID is required' });
    }

    await db.connect();

    // Check if verse exists
    const verse = await db.get('SELECT id FROM verses WHERE id = ?', [verseId]);
    if (!verse) {
      await db.close();
      return res.status(404).json({ error: 'Verse not found' });
    }

    // Check if bookmark already exists
    const existingBookmark = await db.get(
      'SELECT id FROM bookmarks WHERE user_id = ? AND verse_id = ?',
      [req.user.userId, verseId]
    );

    if (existingBookmark) {
      await db.close();
      return res.status(409).json({ error: 'Verse is already bookmarked' });
    }

    // Create bookmark
    const tagsString = Array.isArray(tags) ? tags.join(', ') : (tags || '');
    
    const result = await db.run(`
      INSERT INTO bookmarks (user_id, verse_id, note, tags)
      VALUES (?, ?, ?, ?)
    `, [req.user.userId, verseId, note || '', tagsString]);

    await db.close();

    res.status(201).json({
      message: 'Bookmark created successfully',
      id: result.id
    });

  } catch (error) {
    console.error('Add bookmark error:', error);
    res.status(500).json({ error: 'Failed to create bookmark', message: error.message });
  }
});

// Search endpoint with database integration
app.post('/api/search', async (req, res) => {
  try {
    const { 
      query, 
      books = [], 
      testaments = [], 
      exactPhrase = false,
      caseSensitive = false,
      limit = 50,
      offset = 0 
    } = req.body;

    if (!query || query.trim().length === 0) {
      return res.status(400).json({ error: 'Search query is required' });
    }

    await db.connect();

    // Build the search query
    let searchQuery = `
      SELECT 
        v.id,
        v.chapter,
        v.verse,
        v.text,
        b.name as book_name,
        b.abbreviation as book_abbrev,
        b.testament,
        (b.name || ' ' || v.chapter || ':' || v.verse) as reference
      FROM verses v
      JOIN books b ON v.book_id = b.id
      WHERE 1=1
    `;

    const params = [];

    // Filter by testaments
    if (testaments.length > 0) {
      const placeholders = testaments.map(() => '?').join(',');
      searchQuery += ` AND b.testament IN (${placeholders})`;
      params.push(...testaments);
    }

    // Filter by specific books
    if (books.length > 0) {
      const placeholders = books.map(() => '?').join(',');
      searchQuery += ` AND b.name IN (${placeholders})`;
      params.push(...books);
    }

    // Add text search
    if (exactPhrase) {
      if (caseSensitive) {
        searchQuery += ` AND v.text LIKE ?`;
        params.push(`%${query}%`);
      } else {
        searchQuery += ` AND LOWER(v.text) LIKE LOWER(?)`;
        params.push(`%${query}%`);
      }
    } else {
      // Split query into words for flexible matching
      const words = query.toLowerCase().split(/\s+/).filter(word => word.length > 0);
      if (words.length > 0) {
        const wordConditions = words.map(() => 'v.search_text LIKE ?').join(' AND ');
        searchQuery += ` AND (${wordConditions})`;
        params.push(...words.map(word => `%${word}%`));
      }
    }

    // Add ordering and pagination
    searchQuery += ` ORDER BY b.book_order, v.chapter, v.verse LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const results = await db.all(searchQuery, params);

    // Get total count for pagination
    let countQuery = searchQuery.replace(/SELECT.*?FROM/, 'SELECT COUNT(*) as total FROM');
    countQuery = countQuery.replace(/ORDER BY.*?LIMIT.*?OFFSET.*?$/, '');
    const countParams = params.slice(0, -2); // Remove limit and offset
    const countResult = await db.get(countQuery, countParams);

    await db.close();

    res.json({
      results: results.map(result => ({
        id: result.id,
        reference: result.reference,
        book: result.book_name,
        abbreviation: result.book_abbrev,
        testament: result.testament,
        chapter: result.chapter,
        verse: result.verse,
        text: result.text
      })),
      pagination: {
        total: countResult.total,
        limit,
        offset,
        hasMore: offset + limit < countResult.total
      },
      query: {
        searchTerm: query,
        books,
        testaments,
        exactPhrase,
        caseSensitive
      }
    });

  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed', message: error.message });
  }
});

// Get all books endpoint
app.get('/api/scriptures/books', async (req, res) => {
  try {
    await db.connect();
    
    const books = await db.all(`
      SELECT 
        id,
        name,
        abbreviation,
        testament,
        book_order,
        total_chapters,
        is_section
      FROM books 
      ORDER BY book_order
    `);
    
    await db.close();
    
    // Group books by testament
    const groupedBooks = books.reduce((acc, book) => {
      if (!acc[book.testament]) {
        acc[book.testament] = [];
      }
      acc[book.testament].push({
        id: book.id,
        name: book.name,
        abbreviation: book.abbreviation,
        totalChapters: book.total_chapters,
        isSection: book.is_section
      });
      return acc;
    }, {});
    
    res.json({
      books: groupedBooks,
      total: books.length
    });
    
  } catch (error) {
    console.error('Error fetching books:', error);
    res.status(500).json({ error: 'Failed to fetch books', message: error.message });
  }
});

// Get random verse endpoint
app.get('/api/scriptures/random', async (req, res) => {
  try {
    const { testament } = req.query;
    
    await db.connect();
    
    let query = `
      SELECT 
        v.id,
        v.chapter,
        v.verse,
        v.text,
        b.name as book_name,
        b.abbreviation as book_abbrev,
        b.testament
      FROM verses v
      JOIN books b ON v.book_id = b.id
    `;
    
    const params = [];
    
    if (testament) {
      query += ' WHERE b.testament = ?';
      params.push(testament);
    }
    
    query += ' ORDER BY RANDOM() LIMIT 1';
    
    const verse = await db.get(query, params);
    
    await db.close();
    
    if (!verse) {
      return res.status(404).json({ error: 'No verses found' });
    }
    
    res.json({
      verse: {
        id: verse.id,
        reference: `${verse.book_name} ${verse.chapter}:${verse.verse}`,
        book: verse.book_name,
        abbreviation: verse.book_abbrev,
        testament: verse.testament,
        chapter: verse.chapter,
        verse: verse.verse,
        text: verse.text
      }
    });
    
  } catch (error) {
    console.error('Error fetching random verse:', error);
    res.status(500).json({ error: 'Failed to fetch random verse', message: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 LDS Scripture Search API running on port ${PORT}`);
  console.log(`📖 Ready to search the scriptures!`);
});

module.exports = app;

