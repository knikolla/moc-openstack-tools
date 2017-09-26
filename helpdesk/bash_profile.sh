# script aliases for helpdesk user

if [ "$(id -gn)" == "helpdesk" ]; then
    echo "Welcome to the MOC helpdesk interface.  Type \`moc help\` for instructions."
   
    SCRIPT_DIR='/usr/local/src/moc-tools/production'
 
    moc() {
        if [[ $@ == "help" ]]; then
            command sudo -u moc-tools cat "$SCRIPT_DIR/helpdesk/help.txt" | more
        elif [[ $@ =~ ^reset-password ]]; then
            shift 1
            command sudo -u moc-tools python "$SCRIPT_DIR/reset-password.py" $@
        elif [[ $@ =~ ^grant-access ]]; then
            shift 1
            command sudo -u moc-tools python "$SCRIPT_DIR/addusers.py" $@
        elif [[ $@ =~ ^update-quotas ]]; then
            shift 1
            command sudo -u moc-tools python "$SCRIPT_DIR/set-quotas.py" $@
# This can be uncommented for testing updates to this script without interacting with OpenStack
#        elif [[ $@ == "test" ]]; then
#            command sudo -u moc-tools python "$SCRIPT_DIR/helpdesk/test.py
        else
            echo "$@ is not valid input.  Type 'moc help' to see a list of available commands."
        fi
    }

fi

