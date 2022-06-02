from unit.applications.lang.ruby import TestApplicationRuby
from unit.option import option
from unit.utils import waitforglob


class TestRubyHooks(TestApplicationRuby):
    prerequisites = {'modules': {'ruby': 'all'}}

    def _wait_cookie(self, pattern, count):
        return waitforglob(
            option.temp_dir + '/ruby/hooks/cookie_' + pattern, count
        )

    def test_ruby_hooks_eval(self):
        processes = 2

        self.load('hooks', processes=processes, hooks='eval.rb')

        hooked = self._wait_cookie('eval.*', processes)

        assert hooked, 'hooks evaluated'

    def test_ruby_hooks_on_worker_boot(self):
        processes = 2

        self.load('hooks', processes=processes, hooks='on_worker_boot.rb')

        hooked = self._wait_cookie('worker_boot.*', processes)

        assert hooked, 'on_worker_boot called'

    def test_ruby_hooks_on_worker_shutdown(self):
        processes = 2

        self.load('hooks', processes=processes, hooks='on_worker_shutdown.rb')

        assert self.get()['status'] == 200, 'app response'

        self.load('empty')

        hooked = self._wait_cookie('worker_shutdown.*', processes)

        assert hooked, 'on_worker_shutdown called'

    def test_ruby_hooks_on_thread_boot(self):
        processes = 1
        threads = 2

        self.load(
            'hooks',
            processes=processes,
            threads=threads,
            hooks='on_thread_boot.rb',
        )

        hooked = self._wait_cookie('thread_boot.*', processes * threads)

        assert hooked, 'on_thread_boot called'

    def test_ruby_hooks_on_thread_shutdown(self):
        processes = 1
        threads = 2

        self.load(
            'hooks',
            processes=processes,
            threads=threads,
            hooks='on_thread_shutdown.rb',
        )

        assert self.get()['status'] == 200, 'app response'

        self.load('empty')

        hooked = self._wait_cookie('thread_shutdown.*', processes * threads)

        assert hooked, 'on_thread_shutdown called'

    def test_ruby_hooks_multiple(self):
        processes = 1
        threads = 1

        self.load(
            'hooks',
            processes=processes,
            threads=threads,
            hooks='multiple.rb',
        )

        hooked = self._wait_cookie('worker_boot.*', processes)
        assert hooked, 'on_worker_boot called'

        hooked = self._wait_cookie('thread_boot.*', threads)
        assert hooked, 'on_thread_boot called'
