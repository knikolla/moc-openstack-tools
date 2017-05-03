class InvalidEmailError(Exception):
    """User's email address does not pass basic format validation"""


class ItemExistsError(Exception):
    """Keystone resource already exists and cannot be created"""
    def __init__(self, item_type, item_name):
        msg = "{} exists with the name: {}".format(item_type, item_name)
        super(ItemExistsError, self).__init__(msg)


class ItemNotFoundError(Exception):
    """The specified Keystone resource was not found"""
    def __init__(self, item_type, item_name):
        msg = "No {} found in Keystone with name: {}".format(item_type,
                                                             item_name)
        super(ItemNotFoundError, self).__init__(msg)


class BadEmailRecipient(Exception):
    """If sending failed to one or more recipients, but not all of them."""
    def __init__(self, rdict, subject):
        self.__name__ = 'BadEmailRecipient'
        self.rejected = rdict
        self.message = ("Message '{0}' could not be sent to one or more "
                        "recipients.").format(subject)


class ProjectNotFoundError(Exception):
    """The specified project does not exist"""
    def __init__(self, project_name):
        message = 'Cannot find project: {}'.format(project_name)
        super(ProjectNotFoundError, self).__init__(message)
