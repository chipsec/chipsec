# Chipsec Parser Documentation


# Chipsec XML → HTML Reports

This tool generates human readable reports from Chipsec generated XML log files.

## Usage

Running the *app.py* will launch a Flask server where you can drag-and-drop the Chipsec generated XML file, it will generate a HTML report which you can view/save.

Once you have installed the dependencies with `pip install -r requirements.txt`, or using virtualenv/pipenv, you can run the server using `./run.sh` or or `flask run` in this directory.

### Running with Docker

a Dockerfile is also available, you can build the image

`docker build . -t chipsec_parser`

and run it (binding to port 8080)

`docker run -p 8080:8080 chipsec-parser:latest`

## Interesting Files

`chipsec_parser.py` - Parses Test Suite and Test Cases from XML to Dicts

`app.py` - Flask application

`requirements.txt` - pip requirements file
