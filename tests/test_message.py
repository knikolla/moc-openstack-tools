import os
import mock
import pytest
from collections import Counter

# This is a hack for now until directory structure is sorted
# When this is removed remember to un-ignore E402 in flake8
import sys
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.abspath(os.path.join(TEST_DIR, os.pardir))
sys.path.insert(0, PROJECT_DIR)

from message import Message, TemplateMessage
from moc_exceptions import BadEmailRecipient


def test_template():
    """Test whether template messages are filled in correctly"""
    
    # Keywords and values to be filled into the template
    items = {'item_1': 'First', 'long_keyword_item_2': 'Second',
             'space_3': 'Third Third Third ', 'item_4': 'Fourth',
             'item_5': None}
 
    sender = 'dummy@moc.org'
    receiver = 'dummy@moc.org'
    result = 'First Second\nThird Third Third  Fourth\n'
     
    # TEST_DIR = os.path.dirname(os.path.abspath(__file__))
    template = os.path.abspath(os.path.join(TEST_DIR, 'test_template.txt'))

    msg = TemplateMessage(sender=sender, email=receiver, template=template,
                          **items)
    assert msg.body == result


@mock.patch('message.smtplib.SMTP')
def test_send(mock_smtp):
    """Test the function that sends emails"""
    
    msg_values = {'sender': 'dummy@moc.org',
                  'receiver': 'newuser1@moc.org',
                  'subject': 'Test Message Subject',
                  'body': 'This is a Test.'}

    msg = Message(**msg_values)
   
    # What we expect to be passed to smtplib.SMTP.sendmail()
    expected_string = ("Content-Type: text/plain; charset=\"us-ascii\"\n"
                       "MIME-Version: 1.0\n"
                       "Content-Transfer-Encoding: 7bit\n"
                       "Subject: {subject}\n"
                       "From: {sender}\n"
                       "To: {receiver}\n\n"
                       "{body}").format(**msg_values)

    msg.send()

    mock_smtp.assert_called_with('127.0.0.1', '25')
    
    mock_smtp_rval = mock_smtp.return_value
    assert mock_smtp_rval.starttls.call_count == 1
    assert mock_smtp_rval.ehlo.call_count == 1
    mock_smtp_rval.sendmail.assert_called_with(msg_values['sender'],
                                               [msg_values['receiver']],
                                               expected_string)


@mock.patch('message.smtplib.SMTP')
def test_bademail(mock_smtp):
    """Test that BadEmailRecipient is raised correctly"""
    
    msg_values = {'sender': 'dummy@moc.org',
                  'receiver': 'newuser1@moc.org',
                  'subject': 'Test Message Subject',
                  'body': 'This is a Test.'}
    
    rejected_recipients = ['bademail1@moc.org', 'bademail2@moc.org']

    msg = Message(**msg_values)
     
    mock_smtp.return_value.sendmail.return_value = rejected_recipients
                                                  
    with pytest.raises(BadEmailRecipient) as err:
        msg.send()
    
    expected_message = ("Message '{}' could not be sent to one or more "
                        "recipients.").format(msg_values['subject'])
    assert expected_message == err.value.message
    assert Counter(err.value.rejected) == Counter(rejected_recipients)


@mock.patch('message.open', new_callable=mock.mock_open, create=True)
def _file_dump(mock_open, subject=None, label=None, target_path=None):
    msg_values = {'sender': 'dummy@moc.org',
                  'receiver': 'newuser1@moc.org',
                  'subject': subject,
                  'body': 'This is a Test.'}
    
    # `label` and `target_path` should only be passed to dump_to_file() if
    # explicitly specified in the test call. Omitting them tests the default
    # values.  To achieve this, construct file_dump_kwargs and pass with **
    file_dump_kwargs = {}
    
    if label is not None:
        file_tag = label
        file_dump_kwargs['label'] = label
    elif subject is not None:
        file_tag = subject
    else:
        file_tag = None
    
    # construct the correct path and name of the output file
    expected_file_name = 'newuser1_{0}.txt'.format(file_tag)
    if target_path is not None:
        expected_file_name = '{0}/{1}'.format(target_path.rstrip('/'),
                                              expected_file_name)
        file_dump_kwargs['target_path'] = target_path
    else:
        expected_file_name = '/tmp/{0}'.format(expected_file_name)
    
    msg = Message(**msg_values)
    dumped_file_name = msg.dump_to_file(**file_dump_kwargs)
    
    assert dumped_file_name == expected_file_name
    mock_open.assert_called_with(expected_file_name, 'w')
    
    mock_file_handle = mock_open()
    assert mock_file_handle.write.call_count == 1
    mock_file_handle.write.assert_called_with(msg_values['body'])


def test_file_dump():
    """Test the function which writes email text to a file"""
    
    subject = 'Test Message Subject'
    target_path = '/testdir/'
    label = 'MessageLabel'

    _file_dump()
    _file_dump(subject=subject)
    _file_dump(label=label)
    _file_dump(target_path=target_path)
    _file_dump(subject=subject, label=label)
    _file_dump(subject=subject, target_path=target_path)
    _file_dump(label=label, target_path=target_path)
    _file_dump(subject=subject, label=label, target_path=target_path)
