from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
import markdown
from werkzeug.security import generate_password_hash, check_password_hash
import os
import mistune
from collections import defaultdict
import logging
from urllib.parse import unquote
import shutil
from datetime import datetime
from mistune import Markdown, HTMLRenderer

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # 请更换为随机字符串

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'user', avatar TEXT, bio TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS posts 
                 (id INTEGER PRIMARY KEY, title TEXT, content TEXT, category TEXT, filename TEXT, user_id INTEGER, image_dir TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS post_images 
                 (id INTEGER PRIMARY KEY, post_id INTEGER, filename TEXT)''')
    c.execute('''PRAGMA table_info(users)''')
    columns = [col[1] for col in c.fetchall()]
    if 'role' not in columns:
        c.execute('''ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user' ''')
        logger.debug("Added 'role' column to users table")
    if 'avatar' not in columns:
        c.execute('''ALTER TABLE users ADD COLUMN avatar TEXT''')
        logger.debug("Added 'avatar' column to users table")
    if 'bio' not in columns:
        c.execute('''ALTER TABLE users ADD COLUMN bio TEXT''')
        logger.debug("Added 'bio' column to users table")
    c.execute('''PRAGMA table_info(posts)''')
    columns = [col[1] for col in c.fetchall()]
    if 'image_dir' not in columns:
        c.execute('''ALTER TABLE posts ADD COLUMN image_dir TEXT''')
        logger.debug("Added 'image_dir' column to posts table")
    conn.commit()
    conn.close()

def save_post(title, content, category, filename, user_id, image_dir):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # 使用 Python 获取当前时间
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('INSERT INTO posts (title, content, category, filename, user_id, image_dir, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', 
              (title, content, category, filename, user_id, image_dir, created_at))
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

def generate_toc(content):
    # 自定义 Renderer 用于提取标题
    class TOCRenderer(HTMLRenderer):
        def __init__(self):
            super().__init__()
            self.toc = []
        
        def heading(self, text, level):
            # 为标题生成 ID（去掉特殊字符，转换为小写）
            id = text.lower().replace(' ', '-').replace('#', '').replace(':', '')
            self.toc.append({'text': text, 'level': level, 'id': id})
            return f'<h{level} id="{id}">{text}</h{level}>'
    
    # 创建 Markdown 解析器，使用自定义 Renderer
    markdown = Markdown(renderer=TOCRenderer())
    # 解析 Markdown 内容
    html = markdown(content)
    # 获取大纲
    toc = markdown.renderer.toc
    return toc

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    logger.debug(f"Register request method: {request.method}")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        role = 'user'
        avatar = 'default_avatar.jpg'  # 默认头像
        bio = '请输入您的简介...'  # 默认简介
        
        logger.debug(f"Registering user: {username}")
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password, role, avatar, bio) VALUES (?, ?, ?, ?, ?)', 
                      (username, hashed_password, role, avatar, bio))
            conn.commit()
            logger.debug(f"User {username} registered successfully")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            logger.error(f"Username {username} already exists")
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
        c.execute('SELECT id, password, role, avatar, bio FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user:
            try:
                if check_password_hash(user[1], password):
                    session['user_id'] = user[0]
                    session['role'] = user[2] if user[2] else 'user'
                    session['avatar'] = user[3]  # 保存头像
                    session['bio'] = user[4]     # 保存简介
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
        c.execute('''SELECT posts.id, posts.title, posts.content, posts.category, posts.filename, posts.user_id, users.username 
                     FROM posts JOIN users ON posts.user_id = users.id''')
    else:
        c.execute('''SELECT posts.id, posts.title, posts.content, posts.category, posts.filename, posts.user_id, users.username 
                     FROM posts JOIN users ON posts.user_id = users.id WHERE posts.user_id = ?''', 
                  (session['user_id'],))
    posts = c.fetchall()
    
    # 计算文件总数和类别数
    total_posts = len(posts)
    categories = {}
    for post in posts:
        category = post[3]
        categories[category] = categories.get(category, 0) + 1
    
    # 获取用户信息，处理可能为空的情况
    user_id = session['user_id']  # 确保 user_id 存在
    c.execute('SELECT username, avatar, bio FROM users WHERE id = ?', (user_id,))
    user_info = c.fetchone()
    
    if user_info:
        username, avatar, bio = user_info
    else:
        username = "未知用户"
        avatar = "default_avatar.jpg"  # 默认头像
        bio = "请输入您的简介..."  # 默认简介
    
    conn.close()
    
    categorized_posts = defaultdict(list)
    for post in posts:
        post_id, title, content, category, filename, user_id, username = post
        categorized_posts[category].append({
            'id': post_id,
            'title': title,
            'filename': filename,
            'username': username
        })
    
    return render_template('dashboard.html', categorized_posts=categorized_posts, role=session.get('role'),
                          username=username, avatar=avatar, bio=bio, total_posts=total_posts, categories=categories)

@app.route('/post/<int:post_id>')
def view_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if session.get('role') == 'admin':
        c.execute('SELECT title, content, category FROM posts WHERE id = ?', (post_id,))
    else:
        c.execute('SELECT title, content, category FROM posts WHERE id = ? AND user_id = ?', 
                  (post_id, session['user_id']))
    post = c.fetchone()
    
    if not post:
        conn.close()
        flash('帖子不存在或无权限查看')
        return redirect(url_for('dashboard'))
    
    title, content, category = post
    
    # 获取同类别文章，按创建时间排序，限制为最近 10 篇
    c.execute('''SELECT id, title, created_at FROM posts WHERE category = ? AND id != ? ORDER BY created_at DESC LIMIT 10''', 
              (category, post_id))
    related_posts = c.fetchall()
    
    # 将 related_posts 中的 created_at 转换为 datetime 对象
    related_posts_with_datetime = []
    from datetime import datetime
    for post_id, title, created_at in related_posts:
        if created_at:  # 确保 created_at 不为空
            try:
                # 假设 created_at 是 'YYYY-MM-DD HH:MM:SS' 格式的字符串
                created_at_dt = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                # 如果格式不匹配，使用当前时间作为默认值
                created_at_dt = datetime.now()
            related_posts_with_datetime.append((post_id, title, created_at_dt))
        else:
            related_posts_with_datetime.append((post_id, title, None))
    
    # 生成大纲
    toc = generate_toc(content)
    
    conn.close()
    
    rendered_content = markdown.markdown(content, extensions=['extra', 'fenced_code'])
    logger.debug(f"Rendered content for post {post_id}: {rendered_content}")
    return render_template('post.html', title=title, content=rendered_content, 
                          related_posts=related_posts_with_datetime, toc=toc)

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
        
        # 生成新的图片存储目录：类别/日期
        date_str = datetime.now().strftime('%Y%m%d')  # 格式如 20250223
        image_dir = os.path.join('static', 'images', category, date_str)
        if not os.path.exists(image_dir):
            os.makedirs(image_dir)
        
        # 保存帖子并记录 image_dir
        post_id = save_post(title, content, category, md_file.filename, session['user_id'], image_dir)
        
        # 保存图片并记录到数据库（添加时间戳）
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')  # 格式如 20250223123456
        for img in images:
            if img.filename:
                # 获取文件扩展名
                _, ext = os.path.splitext(img.filename)
                # 生成唯一文件名：原文件名_时间戳.扩展名
                unique_filename = f"{os.path.splitext(img.filename)[0]}_{timestamp}{ext}"
                img_path = os.path.join(image_dir, unique_filename)
                img.save(img_path)
                logger.debug(f"Saved image: {img_path}")
                conn = sqlite3.connect('database.db')
                c = conn.cursor()
                c.execute('INSERT INTO post_images (post_id, filename) VALUES (?, ?)', 
                          (post_id, unique_filename))
                conn.commit()
                conn.close()
        
        # 更新 Markdown 中的图片链接
        for original_link in original_image_links:
            img_filename = unquote(os.path.basename(original_link))
            # 找到匹配的上传图片，生成新文件名
            for uploaded_filename in image_filenames:
                if os.path.basename(img_filename) == os.path.basename(uploaded_filename):
                    _, ext = os.path.splitext(uploaded_filename)
                    new_filename = f"{os.path.splitext(uploaded_filename)[0]}_{timestamp}{ext}"
                    new_url = f'/{image_dir}/{new_filename}'
                    content = content.replace(f'![第一张照片]({unquote(original_link)})', f'![第一张照片]({new_url})')
                    content = content.replace(f'![]( {unquote(original_link)} )', f'![]( {new_url} )')
                    content = content.replace(f'![]({unquote(original_link)})', f'![]({new_url})')
                    content = content.replace(f'![第一张照片]({original_link})', f'![第一张照片]({new_url})')
                    content = content.replace(f'![]( {original_link} )', f'![]( {new_url} )')
                    content = content.replace(f'![]({original_link})', f'![]({new_url})')
                    logger.debug(f"Replacing Markdown pattern with '{new_url}'")
                    break
        
        logger.debug(f"Updated content: {content}")
        update_post_content(post_id, content)
        
        flash('上传成功')
        return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    if session.get('role') == 'admin':
        c.execute('SELECT id, title, content, category, user_id FROM posts WHERE id = ?', (post_id,))
    else:
        c.execute('SELECT id, title, content, category, user_id FROM posts WHERE id = ? AND user_id = ?', 
                  (post_id, session['user_id']))
    post = c.fetchone()
    
    if not post:
        conn.close()
        flash('帖子不存在或无权限编辑')
        return redirect(url_for('dashboard'))
    
    post_id, title, content, category, user_id = post
    
    if request.method == 'POST':
        new_title = request.form['title']
        new_content = request.form['content']
        new_category = request.form['category']
        
        c.execute('UPDATE posts SET title = ?, content = ?, category = ? WHERE id = ?', 
                  (new_title, new_content, new_category, post_id))
        conn.commit()
        conn.close()
        flash('帖子已更新')
        return redirect(url_for('dashboard'))
    
    conn.close()
    return render_template('edit.html', post={'id': post_id, 'title': title, 'content': content, 'category': category})

@app.route('/delete/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        return {'success': False, 'message': '未登录'}, 401
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    if session.get('role') == 'admin':
        c.execute('SELECT id, user_id, image_dir FROM posts WHERE id = ?', (post_id,))
    else:
        c.execute('SELECT id, user_id, image_dir FROM posts WHERE id = ? AND user_id = ?', 
                  (post_id, session['user_id']))
    post = c.fetchone()
    
    if not post:
        conn.close()
        return {'success': False, 'message': '帖子不存在或无权限删除'}, 404
    
    _, _, image_dir = post
    
    # 验证密码
    c.execute('SELECT password FROM users WHERE id = ?', (session['user_id'],))
    hashed_password = c.fetchone()[0]
    password = request.form.get('password')
    if not password or not check_password_hash(hashed_password, password):
        conn.close()
        return {'success': False, 'message': '密码错误，请重新输入！'}, 401
    
    # 删除图片文件
    c.execute('SELECT filename FROM post_images WHERE post_id = ?', (post_id,))
    images = c.fetchall()
    for img in images:
        img_path = os.path.join(image_dir, img[0])
        if os.path.exists(img_path):
            os.remove(img_path)
            logger.debug(f"Deleted image: {img_path}")
    
    # 检查并删除 image_dir（日期文件夹）是否为空
    try:
        if os.path.exists(image_dir) and not os.listdir(image_dir):  # 如果日期文件夹存在且为空
            os.rmdir(image_dir)  # 删除空日期文件夹
            logger.debug(f"Deleted empty directory: {image_dir}")
    except OSError as e:
        logger.error(f"Failed to delete directory {image_dir}: {e}")
    
    # 获取类别文件夹路径（image_dir 的父目录）
    category_dir = os.path.dirname(image_dir)
    
    # 检查并删除类别文件夹是否为空
    try:
        if os.path.exists(category_dir) and not os.listdir(category_dir):  # 如果类别文件夹存在且为空
            os.rmdir(category_dir)  # 删除空类别文件夹
            logger.debug(f"Deleted empty category directory: {category_dir}")
    except OSError as e:
        logger.error(f"Failed to delete category directory {category_dir}: {e}")
    
    # 删除数据库记录
    c.execute('DELETE FROM post_images WHERE post_id = ?', (post_id,))
    c.execute('DELETE FROM posts WHERE id = ?', (post_id,))
    conn.commit()
    conn.close()
    
    return {'success': True, 'message': '帖子及相关目录已删除'}, 200


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('avatar', None)
    session.pop('bio', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)