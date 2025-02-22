from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import markdown
from werkzeug.security import generate_password_hash, check_password_hash
import os
import mistune
from collections import defaultdict
import logging
from urllib.parse import unquote

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # 请更换为随机字符串

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user')''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts 
                 (id INTEGER PRIMARY KEY, title TEXT, content TEXT, category TEXT, filename TEXT, user_id INTEGER)''')
    c.execute('''CREATE TABLE IF NOT EXISTS post_images 
                 (id INTEGER PRIMARY KEY, post_id INTEGER, filename TEXT)''')
    c.execute('''PRAGMA table_info(users)''')
    columns = [col[1] for col in c.fetchall()]
    if 'role' not in columns:
        c.execute('''ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user' ''')
        logger.debug("Added 'role' column to users table")
    conn.commit()
    conn.close()

def save_post(title, content, category, filename, user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO posts (title, content, category, filename, user_id) VALUES (?, ?, ?, ?, ?)', 
              (title, content, category, filename, user_id))
    post_id = c.lastrowid
    conn.commit()
    conn.close()
    return post_id

def update_post_content(post_id, content):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('UPDATE posts SET content = ? WHERE id = ?', (content, post_id))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        role = 'user'
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', 
                      (username, hashed_password, role))
            conn.commit()
            flash('注册成功，请登录！')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('用户名已存在！')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT id, password, role FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user:
            try:
                if check_password_hash(user[1], password):
                    session['user_id'] = user[0]
                    session['role'] = user[2] if user[2] else 'user'
                    flash('登录成功！')
                    return redirect(url_for('dashboard'))
                else:
                    flash('用户名或密码错误！')
            except ValueError as e:
                logger.error(f"Password hash error: {e}")
                flash('密码格式错误，请联系管理员！')
        else:
            flash('用户名或密码错误！')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if session.get('role') == 'admin':
        # 管理员查看所有用户的帖子，关联用户名
        c.execute('''SELECT posts.id, posts.title, posts.content, posts.category, posts.filename, posts.user_id, users.username 
                     FROM posts JOIN users ON posts.user_id = users.id''')
    else:
        # 普通用户仅查看自己的帖子
        c.execute('''SELECT posts.id, posts.title, posts.content, posts.category, posts.filename, posts.user_id, users.username 
                     FROM posts JOIN users ON posts.user_id = users.id WHERE posts.user_id = ?''', 
                  (session['user_id'],))
    posts = c.fetchall()
    conn.close()
    
    categorized_posts = defaultdict(list)
    for post in posts:
        post_id, title, content, category, filename, user_id, username = post
        categorized_posts[category].append({
            'id': post_id,
            'title': title,
            'filename': filename,
            'username': username  # 添加用户名
        })
    
    return render_template('dashboard.html', categorized_posts=categorized_posts, role=session.get('role'))

@app.route('/post/<int:post_id>')
def view_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if session.get('role') == 'admin':
        c.execute('SELECT title, content FROM posts WHERE id = ?', (post_id,))
    else:
        c.execute('SELECT title, content FROM posts WHERE id = ? AND user_id = ?', 
                  (post_id, session['user_id']))
    post = c.fetchone()
    conn.close()
    
    if not post:
        flash('帖子不存在或无权限查看')
        return redirect(url_for('dashboard'))
    
    title, content = post
    rendered_content = markdown.markdown(content, extensions=['extra', 'fenced_code'])
    logger.debug(f"Rendered content for post {post_id}: {rendered_content}")
    return render_template('post.html', title=title, content=rendered_content)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        category = request.form['category']
        md_file = request.files.get('md_file')
        images = request.files.getlist('images')
        
        if not md_file:
            flash('请上传 Markdown 文件')
            return redirect(url_for('upload'))
        
        content = md_file.read().decode('utf-8')
        logger.debug(f"Original content: {content}")
        
        markdown_parser = mistune.Markdown()
        ast = markdown_parser.parse(content)
        logger.debug(f"AST structure: {ast}")
        
        def extract_image_links(nodes):
            image_links = []
            for node in nodes:
                if isinstance(node, dict):
                    if node.get('type') == 'image':
                        attrs = node.get('attrs', {})
                        src = attrs.get('url') or node.get('src') or node.get('dest') or node.get('href')
                        if src:
                            image_links.append(src)
                    if 'children' in node:
                        image_links.extend(extract_image_links(node['children']))
                elif isinstance(node, list):
                    image_links.extend(extract_image_links(node))
            return image_links
        
        original_image_links = extract_image_links(ast)
        logger.debug(f"Extracted image links: {original_image_links}")
        image_links_decoded = [unquote(os.path.basename(link)) for link in original_image_links]
        logger.debug(f"Decoded image links: {image_links_decoded}")
        
        image_filenames = [img.filename for img in images if img.filename]
        logger.debug(f"Uploaded image filenames: {image_filenames}")
        
        missing_images = [url for url in image_links_decoded if url not in image_filenames]
        if missing_images:
            flash('缺少图片文件：' + ', '.join(missing_images))
            return redirect(url_for('upload'))
        
        post_id = save_post(title, content, category, md_file.filename, session['user_id'])
        
        directory = os.path.join('static', 'images', str(post_id))
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        for img in images:
            if img.filename:
                img_filename = img.filename
                img_path = os.path.join(directory, img_filename)
                img.save(img_path)
                logger.debug(f"Saved image: {img_path}")
                conn = sqlite3.connect('database.db')
                c = conn.cursor()
                c.execute('INSERT INTO post_images (post_id, filename) VALUES (?, ?)', 
                          (post_id, img_filename))
                conn.commit()
                conn.close()
        
        for original_link in original_image_links:
            img_filename = unquote(os.path.basename(original_link))
            new_url = f'/static/images/{post_id}/{img_filename}'
            content = content.replace(f'![第一张照片]({unquote(original_link)})', f'![第一张照片]({new_url})')
            content = content.replace(f'![]( {unquote(original_link)} )', f'![]( {new_url} )')
            content = content.replace(f'![]({unquote(original_link)})', f'![]({new_url})')
            content = content.replace(f'![第一张照片]({original_link})', f'![第一张照片]({new_url})')
            content = content.replace(f'![]( {original_link} )', f'![]( {new_url} )')
            content = content.replace(f'![]({original_link})', f'![]({new_url})')
            logger.debug(f"Replacing Markdown pattern with '{new_url}'")
        
        logger.debug(f"Updated content: {content}")
        update_post_content(post_id, content)
        
        flash('上传成功')
        return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('已退出登录！')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)