from flask import Flask, send_from_directory, redirect

# app = Flask(__name__, static_folder='.')
app = Flask(__name__)
application = app  # for AWS compatibility

# Redirect root to 'register.html'
@app.route('/')
def root():
    return redirect('/register.html', code=302)

# Serve 'register.html'
@app.route('/register.html')
def register():
    return send_from_directory(app.static_folder, 'register.html')

# Serve 'dashboard.html'
@app.route('/dashboard.html')
def dashboard():
    return send_from_directory(app.static_folder, 'dashboard.html')

# Serve 'quiz.html'
@app.route('/quiz.html')
def quiz():
    return send_from_directory(app.static_folder, 'quiz.html')

# Serve 'flash.html'
@app.route('/flash.html')
def flash():
    return send_from_directory(app.static_folder, 'flash.html')

# Serve 'ai_chat.html'
@app.route('/ai_chat.html')
def ai_chat():
    return send_from_directory(app.static_folder, 'ai_chat.html')

@app.route('/navbar.css')
def navbar():
    return send_from_directory(app.static_folder, 'navbar.css')

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=8000, debug=True)
