1. Description

A book keeping app for Journalizing, with auto-posting to ledger, and balance sheet preparation.

2. How to run

(i) Install docker cli, if not already installed.

(ii) Then run

docker build -t book_keeping .

(iii) Then run (Note: replace abcd1234 with the username and replace Abcd@1234 with the password you want to keep for the account having admin privileges)

docker run -d --name book_keeping -e ADMIN_USERNAME="abcd1234" -e ADMIN_PASSWORD="Abcd@1234" -p 10000:10000 --rm book_keeping


(iv) Open the http://localhost:10000/ url.
