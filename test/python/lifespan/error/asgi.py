async def application(scope, receive, send):
    if scope['type'] != 'http':
        raise Exception('Exception blah')
