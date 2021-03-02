# CI_CD_DAST

Example Integrations for Veracode DAST into CI/CD Systems.

# create-or-update-da-scan.py

The script relies on environment variables to direct it.  These can be created in your CI/CD system.  It specifically needs:

    1. VeraID            - Your Veracode ID 
    2. VeraPW            - Your Veracode Secret Key
    3. Dyanamic_Target   - The url you wish to scan
    4. Dynamic_User      - The user you need for authenticated scan
    5. Dynamic_Pass      - The password for the user
    6. JOB_NAME          - The Dynamic Analysis name in the plaftorm.  

For this example it assumes the JOB_NAME is the same as the Dynamic Analysis you wish to create/update and that there is a corresponding application to link to with the same name.

The example also assumes the web site can work with Veracode's Dynamic Analysis Auto login feature

To create your Veracode ID/Secret Key you can look here: https://help.veracode.com/r/c_api_credentials3


Note: more examples to come later
