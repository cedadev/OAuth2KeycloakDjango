# OAuth2-Django-Keycloak

Integrating Django with Keycloak using OpenID Connect (OIDC)

## Getting Started
### Run Keycloak Ansible playbook

#####Make sure you have Python3.6+, Ansible and Docker + Docker-ce installed

1. Clone the repository
    ```
    $ git clone https://github.com/cedadev/OAuth2KeycloakDjango.git
    ```
2. Go to `Playbooks` directory

3.  Create a Keycloak admin running on localhost
    ```
    $ ansible-playbook create.yml
    ```
4. Create a client
    ```
    ansible-playbook -i inventory.yml create_client.yml
    ```
5. Create a user

    There are two ways to create a user:
    1) Log into Keycloak: http://localhost:9000. Click on Admin Console. Then, username and password is `admin` / `admin`.
        - Click on _Users_ and then the **Add User** button.
        - Set a username, email, first and last name.
        - Go to the _Credentials_ tab and set a permanent password for this user.
    2) Through Keycloak CLI
        - download the server from https://www.keycloak.org/downloads.html and extract it
        - navigate to `bin` directory
        - connect to the server ```./kcadm.sh config credentials --server http://localhost:9000/auth --realm master --user admin --password admin```
        - create a user ```./kcadm.sh create users -r master -s username=testuser -s enabled=true -s email=test@mail.com -s firstName=First -s lastName=Last```
        - set/reset a  password(`-t` parameter means the password is not temporary) ```./kcadm.sh set-password -r master --username testuser --new-password pass -t=false``` 
        - more information https://access.redhat.com/documentation/en-us/red_hat_single_sign-on/7.1/html/server_administration_guide/admin_cli
        
### Connecting Django and Keycloak


1. Create python3 virtual env
    ```
    $ python3 -m venv keycloak
    ```

2. Activate python3 virtual env
    ```
    $ source keycloak/bin/activate
    ```

3. Install requirements
    ```
    $ pip install -r requirements.txt
    ```

4. Run migrations 
    ```
    $ python manage.py migrate
    ```
5. Go to the _Client Credentials_ tab in the `admin console` and copy the _Secret_. Paste this into the
   Django settings.py file as the value of the _KEYCLOAK_CLIENT_SECRET_ setting.
   
6. Run the server

    ```
    export OAUTHLIB_INSECURE_TRANSPORT=1
    python manage.py runserver
    ```

    - Note: the OAUTHLIB_INSECURE_TRANSPORT env variable is needed since the
      library being used normally doesn't allow OAuth over insecure HTTP. In
      production it wouldn't be needed to set this environment variable because you
      would have SSL certifications for your web application.
   
### Test it

1. First log out of the Keycloak admin console if you are still logged in.

2. Try going to http://localhost:8000/protected/. You should be redirected to Keycloak. Log in as the user you created above.

3. Now you should be redirected back to `/protected/`.

###In order to destroy the Keycloak server run
```
$ ansible-playbook destroy.yml
```
