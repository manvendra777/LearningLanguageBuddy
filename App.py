from flask import Flask, jsonify, request
from flask_cors import CORS
import boto3
from dotenv import load_dotenv
import os
import hmac
import hashlib
import base64

def get_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(str(client_secret).encode('utf-8'),
                   msg=str(message).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2




load_dotenv()  # Load environment variables

app = Flask(__name__)
CORS(app)

# AWS Configuration
aws_access_key_id = 'ACCESS_KEY'
aws_secret_access_key = 'SECRET'
region_name = 'us-west-1'  # Change to your AWS region

# Initialize Boto3 Clients
cognito = boto3.client('cognito-idp', region_name=region_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
dynamodb = boto3.resource('dynamodb', region_name=region_name, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
quizzes_table = dynamodb.Table('Quiz_Beginner')  # Ensure the table is created in DynamoDB

@app.route('/register', methods=['POST'])
def register():
    """
    Register a new user to AWS Cognito
    """
    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')
    client_id = "6mv8228ah6na4rqejfnsu7d21n"
    client_secret = "CLIENT_SECRET"
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
    client_secret = "CLIENT_SECRET"
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
        # Return the ID token and Access token directly from Cognito
        return jsonify({
            'message': 'Login successful',
            'id_token': response['AuthenticationResult']['IdToken'],
            'access_token': response['AuthenticationResult']['AccessToken']
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 401

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

@app.route('/get_flashcards', methods=['GET'])
def get_flashcards():
    """
    Retrieve all flashcards from DynamoDB.
    """
    try:
        flashcards_table = dynamodb.Table('Flash_Beginner')  # Make sure this table exists in your DynamoDB
        response = flashcards_table.scan()
        flashcards = response.get('Items', [])
        if flashcards:
            return jsonify(flashcards), 200
        else:
            return jsonify({'message': 'No flashcards available'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
