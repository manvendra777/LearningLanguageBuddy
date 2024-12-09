from flask import Flask, jsonify, request
from flask import Flask, jsonify, request, session, redirect, url_for
from flask_cors import CORS
import boto3
from dotenv import load_dotenv
import os
import hmac
import hashlib
import base64
import requests
import openai


load_dotenv()

OPENROUTER_API_KEY = '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'  # Replace with your OpenRouter API key
OPENROUTER_API_URL = 'https://openrouter.ai/api/v1/completions'

openai.api_base = "https://openrouter.ai/api/v1"
openai.api_key = OPENROUTER_API_KEY

ACCESS_KEY = os.getenv("aws_access_key_id")
SECRET = os.getenv("aws_secret_access_key")
CLIENT_SECRET = os.getenv("client_secret")
def get_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(str(client_secret).encode('utf-8'),
                   msg=str(message).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = 'myKey1234'

# Initialize Boto3 Clients
cognito = boto3.client('cognito-idp', region_name='us-west-1', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET)
dynamodb = boto3.resource('dynamodb', region_name='us-west-1', aws_access_key_id=ACCESS_KEY, aws_secret_access_key=SECRET)
users_table = dynamodb.Table('Users')  # Reference to the 'Users' table
response = users_table.scan()
<<<<<<< HEAD
print(response)
=======
>>>>>>> 5ddeb98d10a0733504a90ff3e5786e51d6a819b2

@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user to AWS Cognito
    """
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    client_id = "6mv8228ah6na4rqejfnsu7d21n"
    client_secret = CLIENT_SECRET
    secret_hash = get_secret_hash(username, client_id, client_secret)

    try:
        # Register the user in AWS Cognito
        response = cognito.sign_up(
            ClientId='6mv8228ah6na4rqejfnsu7d21n',
            SecretHash=secret_hash,
            Username=username,
            Password=password,
            UserAttributes=[
                {'Name': 'email', 'Value': email}
            ]
        )
        # Add the user to the DynamoDB Users table with default level
        users_table.put_item(
            Item={
                'username': username,
                'email': email,
                'score': 0
                  
            }
        )
        return jsonify({'message': 'User registered successfully', 'user': response}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and return Cognito tokens
    """
    username = request.json.get('username')
    password = request.json.get('password')
    client_id = "6mv8228ah6na4rqejfnsu7d21n"
    client_secret = CLIENT_SECRET
    secret_hash = get_secret_hash(username, client_id, client_secret)

    try:
        # Authenticate with AWS Cognito
        response = cognito.initiate_auth(
            ClientId='6mv8228ah6na4rqejfnsu7d21n',
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )
        session['username'] = username
        # Return the ID token and Access token directly from Cognito
        return jsonify({
            'message': 'Login successful',
            'redirect_url': 'http://localhost:8000/quiz.html'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 401

@app.route('/logout', methods=['POST'])
def logout():
    """
    Clear the session to log out the user.
    """
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

<<<<<<< HEAD
# @app.route('/get_all_questions', methods=['GET'])
# def get_all_questions():
#     """
#     Retrieve all quiz questions from DynamoDB.
#     """
#     try:
#         response = quizzes_table.scan()
#         questions = response.get('Items', [])
#         if questions:
#             # Shuffle or randomize questions if needed
#             import random
#             random.shuffle(questions)
#             return jsonify(questions), 200
#         else:
#             return jsonify({'message': 'No questions available'}), 404
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
=======
@app.route('/get_all_questions', methods=['GET'])
def get_all_questions():
    """
    Retrieve all quiz questions from DynamoDB.
    """
    try:
        response = quizzes_table.scan()
        questions = response.get('Items', [])
        if questions:
            # Shuffle or randomize questions if needed
            import random
            random.shuffle(questions)
            return jsonify(questions), 200
        else:
            return jsonify({'message': 'No questions available'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500
>>>>>>> 5ddeb98d10a0733504a90ff3e5786e51d6a819b2

@app.route('/get_questions_by_score', methods=['POST'])
def get_questions_by_score():
    """
    Retrieve questions from the appropriate table based on the user's score.
    """
    username = session.get('username')
    tableInfo = users_table.get_item(Key={'username': username})
    score = tableInfo.get('Item', {}).get('score', 0)
    if not username:
        return jsonify({'error': 'Unauthorized access. Please log in.'}), 401
    if score < 100:
        table_name = 'Quiz_Beginner'
    elif score > 200:
        table_name = 'Quiz_Advanced'
    else:
        table_name = 'Quiz_Intermediate'

    try:
        quiz_table = dynamodb.Table(table_name)  # Dynamically select the table
        response = quiz_table.scan()
        questions = response.get('Items', [])
        if questions:
            import random
            random.shuffle(questions)  # Shuffle questions for randomness
            return jsonify({'username': username, 'questions': questions, 'score': score}), 200
        else:
            return jsonify({'message': f'No questions available in {table_name}'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/update_score', methods=['POST'])
def update_score():
    """
    Update the user's score based on the quiz result and update their level in the Users table.
    """
    username = session.get('username')  # Assume username is passed in the request
    tableInfo = users_table.get_item(Key={'username': username})
    score = tableInfo.get('Item', {}).get('score', 0)
    result = request.json.get('result')  # 'correct' or 'wrong'

    # Update score based on result
    if result == 'correct':
        score += 10  # Increment score for correct answers
    elif result == 'wrong':
        score -= 5  # Decrement score for wrong answers

    # Ensure score does not drop below zer
    if score < 0:
        score = 0

    # Determine proficiency level
    if score < 100:
        level = 'beginner'
    elif score > 200:
        level = 'advanced'
    else:
        level = 'intermediate'

    try:
        response = users_table.get_item(Key={'username': username})
        current_level = response.get('Item', {}).get('score', 0)

        # Update the level in the Users table if it has changed
        if current_level != level:
            users_table.update_item(
                Key={'username': username},
                UpdateExpression='SET score = :score',
                ExpressionAttributeValues={':score': score}
            )
        return jsonify({'score': score, 'level': level}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/evaluate_answer', methods=['POST'])
def evaluate_answer():
    """
    Receive a user's answer and the question text, evaluate it, and return whether it's correct.
    """
    question_text = request.json.get('question_text')
    user_answer = request.json.get('answer')

    try:
        # Scan to find the matching question by its text
        response = quizzes_table.scan(
            FilterExpression='question = :question',
            ExpressionAttributeValues={':question': question_text}
        )
        question = response['Items'][0] if response['Items'] else None
        if not question:
            return jsonify({'error': 'Question not found'}), 404

        correct_answer = question['solution']
        result = 'correct' if user_answer == correct_answer else 'wrong'
        return jsonify({'result': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_flashcards', methods=['POST'])
def get_flashcards():
    """
    Retrieve all flashcards from DynamoDB.
    """
    username = session.get('username')
    tableInfo = users_table.get_item(Key={'username': username})
    score = tableInfo.get('Item', {}).get('score', 0)
    if not username:
        return jsonify({'error': 'Unauthorized access. Please log in.'}), 401
    # Determine the correct table based on the score
    if score < 100:
        table_name = 'Flash_Beginner'
    elif score > 200:
        table_name = 'Flash_Advanced'
    else:
        table_name = 'Flash_Intermediate'

    try:
        flashcards_table = dynamodb.Table(table_name)  # Make sure this table exists in your DynamoDB
        response = flashcards_table.scan()
        flashcards = response.get('Items', [])
        if flashcards:
            import random
            random.shuffle(flashcards)
            return jsonify({'flashcards': flashcards, 'score' : score}), 200
        else:
            return jsonify({'message': 'No flashcards available'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/chat_ai', methods=['POST'])
def chat_ai():
    """
    Handle AI chat interactions using OpenRouter API with openai.ChatCompletion.create.
    """
    user_message = request.json.get('message', '')

    try:
        # Create the chat completion
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # Replace with your desired model
            messages=[
                {"role": "system", "content": "You are an English learning assistant."},
                {"role": "user", "content": user_message}
            ],
            headers={
                "HTTP-Referer": "http://localhost:8000",  # Optional, update with your app's URL
                "X-Title": "AI English Learning Chat"  # Optional, name of your app
            }
        )

        # Extract the AI's response
        ai_message = response['choices'][0]['message']['content']
        return jsonify({'response': ai_message}), 200
    except openai.error.OpenAIError as e:
        print(f"OpenAI API Error: {e}")
        return jsonify({'error': f"Request failed: {e}"}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)