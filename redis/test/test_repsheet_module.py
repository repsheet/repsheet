import redis

connection = redis.Redis(host='localhost', port=6379)

def test_redis_available():
    assert connection.ping()

def test_blacklist():
    response = connection.execute_command('REPSHEET.BLACKLIST', '1.1.1.1', 'blacklist test')

    assert response == b"OK"
    assert connection.exists('1.1.1.1:repsheet:ip:blacklisted')
    assert connection.get('1.1.1.1:repsheet:ip:blacklisted') == b"blacklist test"

def test_whitelist():
    response = connection.execute_command('REPSHEET.WHITELIST', '1.1.1.1', 'whitelist test')

    assert response == b"OK"
    assert connection.exists('1.1.1.1:repsheet:ip:whitelisted')
    assert connection.get('1.1.1.1:repsheet:ip:whitelisted') == b"whitelist test"


def test_mark():
    response = connection.execute_command('REPSHEET.MARK', '1.1.1.1', 'mark test')

    assert response == b"OK"
    assert connection.exists('1.1.1.1:repsheet:ip:marked')
    assert connection.get('1.1.1.1:repsheet:ip:marked') == b"mark test"

def test_status():
    status, reason = connection.execute_command('REPSHEET.STATUS', '1.1.1.1')
    assert status == b"WHITELISTED"
    assert reason == b"whitelist test"

def test_version():
    version = connection.execute_command('REPSHEET.VERSION')
    assert version == b"0.0.7"
