from unit.applications.lang.ruby import ApplicationRuby
from unit.option import option
from unit.utils import waitforglob
from packaging import version

prerequisites = {
    'modules': {'ruby': lambda v: version.parse(v) >= version.parse('3.0')}
}

client = ApplicationRuby()


def wait_cookie(pattern, count):
    return waitforglob(f'{option.temp_dir}/ruby/hooks/cookie_{pattern}', count)


def test_ruby_hooks_eval():
    processes = 2

    client.load('hooks', processes=processes, hooks='eval.rb')

    hooked = wait_cookie('eval.*', processes)

    assert hooked, 'hooks evaluated'


def test_ruby_hooks_on_worker_boot():
    processes = 2

    client.load('hooks', processes=processes, hooks='on_worker_boot.rb')

    hooked = wait_cookie('worker_boot.*', processes)

    assert hooked, 'on_worker_boot called'


def test_ruby_hooks_on_worker_shutdown():
    processes = 2

    client.load('hooks', processes=processes, hooks='on_worker_shutdown.rb')

    assert client.get()['status'] == 200, 'app response'

    client.load('empty')

    hooked = wait_cookie('worker_shutdown.*', processes)

    assert hooked, 'on_worker_shutdown called'


def test_ruby_hooks_on_thread_boot():
    processes = 1
    threads = 2

    client.load(
        'hooks',
        processes=processes,
        threads=threads,
        hooks='on_thread_boot.rb',
    )

    hooked = wait_cookie('thread_boot.*', processes * threads)

    assert hooked, 'on_thread_boot called'


def test_ruby_hooks_on_thread_shutdown():
    processes = 1
    threads = 2

    client.load(
        'hooks',
        processes=processes,
        threads=threads,
        hooks='on_thread_shutdown.rb',
    )

    assert client.get()['status'] == 200, 'app response'

    client.load('empty')

    hooked = wait_cookie('thread_shutdown.*', processes * threads)

    assert hooked, 'on_thread_shutdown called'


def test_ruby_hooks_multiple():
    processes = 1
    threads = 1

    client.load(
        'hooks',
        processes=processes,
        threads=threads,
        hooks='multiple.rb',
    )

    hooked = wait_cookie('worker_boot.*', processes)
    assert hooked, 'on_worker_boot called'

    hooked = wait_cookie('thread_boot.*', threads)
    assert hooked, 'on_thread_boot called'
