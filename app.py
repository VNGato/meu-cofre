import sqlite3
import re
from flask import Flask, render_template, request, redirect, url_for, flash, session
from cryptography.fernet import Fernet
import os
import secrets
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'meu_cofre_segredo_2026'

# --- CONFIGURAÇÃO DE SEGURANÇA ---
# Gera uma chave de criptografia se ela não existir
KEY_FILE = 'key.key'
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
else:
    with open(KEY_FILE, 'rb') as f:
        key = f.read()

cipher = Fernet(key)

def check_password_strength(password):
    """Verifica a força da senha e retorna a pontuação"""
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Mínimo de 8 caracteres")
    
    if len(password) >= 12:
        score += 1
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Inclua letras maiúsculas")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Inclua letras minúsculas")
    
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Inclua números")
    
    if re.search(r'[^A-Za-z0-9]', password):
        score += 1
    else:
        feedback.append("Inclua caracteres especiais")
    
    return score, feedback

def generate_secure_password():
    """Gera uma senha segura aleatória"""
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
    password = ''.join(secrets.choice(chars) for _ in range(16))
    return password

def validate_input(data):
    """Valida os dados de entrada"""
    errors = []
    
    if not data.get('site', '').strip():
        errors.append("O campo Site/App é obrigatório")
    elif len(data['site']) > 100:
        errors.append("Site/App deve ter no máximo 100 caracteres")
    
    if not data.get('username', '').strip():
        errors.append("O campo Usuário/E-mail é obrigatório")
    elif len(data['username']) > 100:
        errors.append("Usuário/E-mail deve ter no máximo 100 caracteres")
    
    if not data.get('password', '').strip():
        errors.append("O campo Senha é obrigatório")
    elif len(data['password']) > 200:
        errors.append("Senha deve ter no máximo 200 caracteres")
    
    if data.get('url') and len(data['url']) > 200:
        errors.append("URL deve ter no máximo 200 caracteres")
    
    if data.get('notes') and len(data['notes']) > 1000:
        errors.append("Notas devem ter no máximo 1000 caracteres")
    
    return errors

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Tentar criar a tabela com a nova estrutura
    try:
        cursor.execute('''
            CREATE TABLE access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                url TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
    except sqlite3.OperationalError:
        # Se a tabela já existe, verificar se a coluna created_at existe
        try:
            cursor.execute("SELECT created_at FROM access LIMIT 1")
        except sqlite3.OperationalError:
            # Se a coluna não existir, precisamos recriar a tabela
            cursor.execute('DROP TABLE IF EXISTS access')
            cursor.execute('''
                CREATE TABLE access (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    site TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    url TEXT,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM access ORDER BY site COLLATE NOCASE ASC')
    data = cursor.fetchall()
    
    # Descriptografar senhas para exibir na tela
    decrypted_data = []
    for item in data:
        try:
            dec_pass = cipher.decrypt(item[3].encode()).decode()
            decrypted_data.append((item[0], item[1], item[2], dec_pass, item[4], item[5]))
        except:
            decrypted_data.append((item[0], item[1], item[2], '*** ERRO DECRIPTO ***', item[4], item[5]))
    
    conn.close()
    return render_template('index.html', data=decrypted_data)

@app.route('/add', methods=['POST'])
def add():
    # Validar entrada
    errors = validate_input(request.form)
    
    if errors:
        for error in errors:
            flash(error, 'danger')
        return redirect(url_for('index'))
    
    site = request.form['site'].strip()
    user = request.form['username'].strip()
    password = request.form['password']
    url = request.form['url'].strip() if request.form['url'] else None
    notes = request.form['notes'].strip() if request.form['notes'] else None

    # Verificar força da senha
    password_score, password_feedback = check_password_strength(password)
    
    if password_score < 3:
        flash(f'Senha fraca detectada. Considere usar uma senha mais forte. Dicas: {", ".join(password_feedback)}', 'warning')
    else:
        flash('Senha forte detectada!', 'success')

    # Criptografar a senha antes de salvar
    try:
        encrypted_password = cipher.encrypt(password.encode()).decode()
    except Exception as e:
        flash(f'Erro ao criptografar senha: {str(e)}', 'danger')
        return redirect(url_for('index'))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO access (site, username, password, url, notes) VALUES (?, ?, ?, ?, ?)',
                       (site, user, encrypted_password, url, notes))
        conn.commit()
        flash(f'✅ Acesso para {site} salvo com sucesso!', 'success')
    except Exception as e:
        flash(f'❌ Erro ao salvar acesso: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('index'))

@app.route('/edit/<int:id>', methods=['GET'])
def edit(id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM access WHERE id = ?', (id,))
    item = cursor.fetchone()
    
    conn.close()
    
    if item:
        try:
            dec_pass = cipher.decrypt(item[3].encode()).decode()
            return render_template('edit.html', 
                                 item=(item[0], item[1], item[2], dec_pass, item[4], item[5]))
        except:
            flash('❌ Erro ao descriptografar senha', 'danger')
            return redirect(url_for('index'))
    else:
        flash('⚠️ Registro não encontrado', 'warning')
        return redirect(url_for('index'))

@app.route('/update/<int:id>', methods=['POST'])
def update(id):
    # Validar entrada
    errors = validate_input(request.form)
    
    if errors:
        for error in errors:
            flash(error, 'danger')
        return redirect(url_for('edit', id=id))
    
    site = request.form['site'].strip()
    user = request.form['username'].strip()
    password = request.form['password']
    url = request.form['url'].strip() if request.form['url'] else None
    notes = request.form['notes'].strip() if request.form['notes'] else None

    # Verificar força da senha
    password_score, password_feedback = check_password_strength(password)
    
    if password_score < 3:
        flash(f'Senha fraca detectada. Considere usar uma senha mais forte. Dicas: {", ".join(password_feedback)}', 'warning')
    else:
        flash('Senha forte detectada!', 'success')

    # Criptografar a senha antes de salvar
    try:
        encrypted_password = cipher.encrypt(password.encode()).decode()
    except Exception as e:
        flash(f'Erro ao criptografar senha: {str(e)}', 'danger')
        return redirect(url_for('edit', id=id))

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        cursor.execute('UPDATE access SET site = ?, username = ?, password = ?, url = ?, notes = ? WHERE id = ?',
                       (site, user, encrypted_password, url, notes, id))
        conn.commit()
        flash(f'✅ Acesso para {site} atualizado com sucesso!', 'success')
    except Exception as e:
        flash(f'❌ Erro ao atualizar acesso: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('index'))

@app.route('/delete/<int:id>')
def delete(id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Obter informações antes de excluir
    cursor.execute('SELECT site FROM access WHERE id = ?', (id,))
    item = cursor.fetchone()
    
    cursor.execute('DELETE FROM access WHERE id = ?', (id,))
    conn.commit()
    
    if item:
        flash(f'🗑️ Acesso para {item[0]} excluído com sucesso!', 'success')
    else:
        flash('⚠️ Registro não encontrado', 'warning')
    
    conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)