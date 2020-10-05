async def application(scope, receive, send):
    assert scope['type'] == 'http'
