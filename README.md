# OAuth2-Django-Keycloak

Integrating Django with Keycloak using OpenID Connect (OIDC)

## Getting Started

### Run Keycloak in Docker container

```
docker run -d -p 9000:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin jboss/keycloak
```

### Run Django

Make sure you have Python 3.6+ installed.

1.  Install requirements

    ```
    pip install -r requirements.txt
    ```

2.  Run migrations

    ```
    python manage.py migrate
    ```

3.  Run the server

    ```
    (Linux/Mac users): export OAUTHLIB_INSECURE_TRANSPORT=1
    (Windows users): set OAUTHLIB_INSECURE_TRANSPORT=1
    python manage.py runserver
    ```

    - Note: the OAUTHLIB_INSECURE_TRANSPORT env variable is needed since the
      library being used normally doesn't allow OAuth over insecure HTTP. In
      production it wouldn't be needed to set this environment variable because you
      would have SSL certifications for your web application.

### Connecting Django and Keycloak

1. Log into Keycloak: http://localhost:9000. Username and password is `admin` / `admin`.

2. Click on _Clients_ and then click on the **Create** button.

   - Set the client ID to `django`
   - Set access type to _confidential_
   - Add a Valid Redirect URI of `http://localhost:8000/callback/*`
   - Click the **Save** button

3. Create a user to test with. Click on _Users_ and then the **Add User** button.

   - Set a username, email, first and last name.
   - Go to the _Credentials_ tab and set a permanent password for this user.

4. Go to the _Client Credentials_ tab and copy the _Secret_. Paste this into the
   Django settings.py file as the value of the _KEYCLOAK_CLIENT_SECRET_ setting.

### Test it out

1. First log out of the Keycloak admin console if you are still logged in.

2. Try going to http://localhost:8000/protected/. You should be redirected to Keycloak. Log in as the user you created above.

3. Now you should be redirected back to `/protected/`.
