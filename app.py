from flask import Flask, render_template, request
from gen_data import DomainWeaknessAnalysis
import validators
import markdown
import argparse
import json

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/analysis', methods=['GET'])
def analysis():
    domain_name = request.args.get('name')
    if not validators.domain(domain_name):
        return render_template('index.html', error='Invalid domain name')
    
    result = DomainWeaknessAnalysis(domain_name)
    
    if args.debug:
        with open('debug.json', 'r') as f:
            res = json.load(f)
    else:
        res = result.parse()
    clean_value(res)
    summary = result.get_summary(json.dumps(res, indent=4, default=str))

    summary = markdown.markdown(summary)
    return render_template('analysis.html', result=res, summary=summary)

def clean_value(res):
    for key, value in list(res.items()):
        if key == 'whois_data':
            for k, v in list(value.items()):
                if isinstance(v, list):
                    res[key][k] = '<br>'.join(v)
                elif v == None:
                    del res[key][k]
    
@app.template_filter('snake_case_to_normal')
def snake_case_to_normal(value):
    return ' '.join(word.capitalize() for word in value.split('_'))

@app.template_filter('except_first')
def except_first(value):
    return list(value)[1:]

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    app.debug = args.debug
    app.run('0.0.0.0')
