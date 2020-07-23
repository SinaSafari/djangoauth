# Django RESTful authentication app

> uses [django rest framework]('https://www.django-rest-framework.org/')

***

## running the app

- first create a virtual environment.

```sh
python3 -m venv venv
```

for activating the virtual environment

```sh
source ./venv/bin/activate
```

- by default django uses [Sqlite]('') as database and first you should mgrate the models in the database

```sh
python manage.py makemigrations && python manage.py migrate
```

- now you can run the application

```sh
python manage.py runserver
```

the app is up and running on you local machine on port 8000  

***

## models

in custom user model (which is used for authentication) I used email and password instead of the django default way of authentication (by username and password). \
also I add ```is_verified``` field and the user should verify the account by the link in the email provided by user in registration proccess.  

## routes / views

- auth

  - /auth/register
  - auth/login
  - /auth/email-verification
  - /auth/token/refresh
  - /auth/request-reset-email
  - /auth/password-reset/```<uidb64>```/```<token>```
  - /auth/password-reset-complete

***

### 3rd party packages

- [django]('https://www.djangoproject.com/')
- [django rest ramework]('https://www.django-rest-framework.org/')
- [django rest frmaework simple jwt]('https://django-rest-framework-simplejwt.readthedocs.io/en/latest/')
- [drf-yasg]('https://drf-yasg.readthedocs.io/en/stable/')

***

### notes

1. index url of the app (in development is ```http://localhost:8000```), is the swagger documentation. you can use it client for communicate with server.  
2. I tried to make the code well documented and details of each route and view and serializers are provided in the code.
3. email and password of email you want to use as sende of verification email should be in the ```.env``` file. the sample is provided in repo.
