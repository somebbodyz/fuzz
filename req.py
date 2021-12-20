from json.decoder import JSONDecodeError
import requests
import jwt
import json
import argparse
import urllib3
import re



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parseJsonAndInsertPayload(jsonPayloadString, payload):
	if re.search('\$\$', jsonPayloadString):
		jsonWithPayload = re.sub('\$\$', payload, jsonPayloadString)
	else:
		print("Json must be with $$ pattern, this is the place where payload will be inserted")
		exit()
	return jsonWithPayload

def parseWordlist(file):
	with open(file, 'r') as f:
		nums = f.read().splitlines()
	return nums

def send_request(data, url, headers):
	# headers = {'Authorization':api_key , 'X-Jws-Signature': jwt_token, 'Content-type': 'application/json' }
	response = requests.post(url,data=data,headers=headers,verify=False)
	return response

def filter(index, responseObject, filterMode, codes):
	if filterMode == "match":
		if str(responseObject.status_code) in codes:
			print("{} -\t{}\t{}\t{}".format(index+1, responseObject.status_code, len(responseObject.content), responseObject.elapsed.total_seconds()))
	elif filterMode == "hide":
		if str(responseObject.status_code) not in codes:
			print("{} -\t{}\t{}\t{}".format(index+1, responseObject.status_code, len(responseObject.content), responseObject.elapsed.total_seconds()))
	else:
		print("{} -\t{}\t{}\t{}".format(index+1, responseObject.status_code, len(responseObject.content), responseObject.elapsed.total_seconds()))
	

def main():
	parser = argparse.ArgumentParser(description='req')
	parser.add_argument("-w", "--wordlist", required=True, metavar="FILE", help="File with payloads that inserts instead of '$$' in json")
	parser.add_argument("-p", "--jsonpayload", required=True, help="File with json to send", metavar="FILE")
	parser.add_argument("-u", "--url", required=True, metavar="URL")
	parser.add_argument("-H", "--headers", metavar="DICT", default='{}')
	parser.add_argument("-jt", "--jwt-token", dest="jwtToken", nargs=2, help="Token args: HEADER_TO_INSERT SECRET(or private key file if alg RS256)", metavar="STRING")
	parser.add_argument("-ja", "--jwt-algorithm", dest="jwtAlgorithm", default='HS256', help="HS256 (default) or RS256", metavar="STRING")
	parser.add_argument("-mc", "--match-codes", dest="matchCodes")
	parser.add_argument("-hc", "--hide-codes", dest="hideCodes")

	args            = parser.parse_args()
	jsonPayloadFile = args.jsonpayload
	url 			= args.url
	wordlist 		= args.wordlist
	headers 		= args.headers
	jwtToken 		= args.jwtToken
	jwtAlgorithm	= args.jwtAlgorithm
	matchCodes		= args.matchCodes
	hideCodes		= args.hideCodes
	try:
		headers 	= json.loads(headers)
	except JSONDecodeError as e:
		print("Error: Something wrong with dict object in HEADERS")
		exit()

	if jwtAlgorithm == "RS256":
		with open(jwtToken[1], 'rb') as f:
			rs256PrivateKey = f.read()
			jwtToken[1] = rs256PrivateKey #Replace name of Private Key file to private key string
	elif jwtAlgorithm == "HS256":
		pass
	else:
		print("Error: wrong algorithm choose between HS256 and RS256")
		exit()

	if matchCodes:
		filterCodes = matchCodes.split(',')
		filterMode = "match"
	elif hideCodes:
		filterCodes = hideCodes.split(',')
		filterMode = "hide"
	else:
		filterCodes = []
		filterMode = None

	wordlist = parseWordlist(wordlist)
	with open(jsonPayloadFile, 'r') as f:
				jsonPayloadString = f.read()

	#1 step
	#Generate list of valid jsons and format them to json (json.loads)
	listOfJsons = []
	listOfJsonsStrings = []
	listOfjwtTokens = []
	for word in wordlist:
		jsonWithPayload = parseJsonAndInsertPayload(jsonPayloadString, word)
		listOfJsonsStrings.append(jsonWithPayload)
		formattedJson = json.loads(jsonWithPayload)
		listOfJsons.append(formattedJson)

	if jwtToken:
		for Json in listOfJsons:
			listOfjwtTokens.append(jwt.encode(Json, jwtToken[1], jwtAlgorithm))

	#2 step
	#ATTACK
	print("#  \tCODE\tLength\tTime")
	for i in range(len(listOfJsons)):
		if jwtToken:
			headers.update({jwtToken[0]:listOfjwtTokens[i]})
		resp = send_request(listOfJsonsStrings[i],url, headers)
		filter(i, resp, filterMode, filterCodes)
			

main()