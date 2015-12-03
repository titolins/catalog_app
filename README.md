## Catalog App
#### About
* This is the third exercise required for the completion of Udacity's [Full Stack Web Developer Nanodegree's.](https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004)

* The objective of this exercise was to create an web application able to provide a list of items registered within certain categories. The application should also provide a user registration and authentication system based on third-party OAuth providers, allowing registered users to create, edit and delete items. Any user, registered or not, may browse the items.


#### Requirements
* [Python 2.7.8](https://www.python.org)
* [pip](https://pypi.python.org/pypi/pip) -- package manager that we are going to use for installing the required python's packages


#### Instructions
* Download and install python 2.7.8
* Download and install pip
* Clone this repository
* Change into the cloned directory and install the required python packages by issuing the following command:
```bash
pip install -r requirements.txt
```
* Change into the app's package directory and create the database:
```bash
cd catalog_app
python database_setup.py
```
* Change back to the last directory and run the development server with:
```bash
cd ../
python runserver.py
```
* Now open your browser and access http://localhost:5000/

---------------
######Author: Tito Lins
######Date: 2015-12-02
