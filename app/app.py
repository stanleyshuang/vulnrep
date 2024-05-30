from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/')
def hello():
	return "Hello World!"

@app.route('/info')
def info():

	resp = {
		'host': request.headers['Host'],
		'user-agent': request.headers['User-Agent']
	}

	if 'X-Real-IP' in request.headers:
		resp['connecting_ip'] = request.headers['X-Real-IP']

	if 'X-Forwarded-For' in request.headers:
		resp['proxy_ip'] = request.headers['X-Forwarded-For']

	return jsonify(resp)

@app.route('/flask-health-check')
def flask_health_check():
	return "success"
