<header class="w-full border-b border-gray-200 bg-white">
    <div class="mx-auto w-full max-w-[75%] px-4 py-3">
        <div class="flex items-center justify-between gap-4">

            {{-- Left: Brand --}}
            <div class="flex items-center gap-3">
                <a href="#" class="text-lg font-semibold text-gray-900">
                    {{ config('app.name', 'Laravel') }}
                </a>

                <span class="hidden sm:inline-block text-sm text-gray-500">
                    Admin
                </span>
            </div>

            <nav class="md:flex items-center gap-2">
                <a
                    href="{{ route('keys.index') }}"
                    class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                >
                    Keys
                </a>
               --
                <a
                    href="{{ route('notification_logs.index') }}"
                    class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                >
                    Notifications Logs
                </a>
 --
                <a
                    href="{{ route('companies.index') }}"
                    class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                >
                    Company
                </a>

            </nav>

            <div class="flex items-center gap-2">
                @if (Route::has('login'))
                    @auth
                        <span class="hidden sm:inline text-sm text-gray-600">
                            {{ auth()->user()->name ?? auth()->user()->email }}
                        </span>

                        <a
                            href="{{ url('/profile') }}"
                            class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                        >
                            Profile
                        </a>

                        {{-- If you are using Breeze/Jetstream logout route --}}
                       {{-- <form method="POST" action="{{ route('logout') }}">
                            @csrf
                            <button
                                type="submit"
                                class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                            >
                                Logout
                            </button>
                        </form>--}}
                    @else
                        <a
                            href="{{ route('login') }}"
                            class="rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                        >
                            Log in
                        </a>

                        @if (Route::has('register'))
                            <a
                                href="{{ route('register') }}"
                                class="rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white hover:bg-gray-800"
                            >
                                Register
                            </a>
                        @endif
                    @endauth
                @endif
            </div>
        </div>
    </div>
</header>
