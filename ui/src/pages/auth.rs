use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use crate::components::layout::Card;

#[component]
pub fn LoginPage() -> impl IntoView {
    let (email, set_email) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (loading, set_loading) = signal(false);
    let (error, set_error) = signal(None::<String>);

    let navigate = use_navigate();

    let login = Action::new_local(move |_: &()| {
        let navigate = navigate.clone();
        async move {
            set_loading.set(true);
            set_error.set(None);

            // TODO: Implement actual authentication
            // For now, simulate API call
            gloo_timers::future::TimeoutFuture::new(1000).await;

            if email.get() == "admin@ghostcp.com" && password.get() == "password" {
                // Success - redirect to dashboard
                navigate("/dashboard", Default::default());
            } else {
                set_error.set(Some("Invalid credentials".to_string()));
            }

            set_loading.set(false);
        }
    });

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        login.dispatch(());
    };
    
    view! {
        <div class="min-h-screen bg-gray-50 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
            <div class="max-w-md w-full space-y-8">
                <div>
                    <img class="mx-auto h-12 w-auto" src="/logo.svg" alt="GhostCP"/>
                    <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
                        "Sign in to your account"
                    </h2>
                </div>
                
                <Card>
                    <form class="space-y-6" on:submit=on_submit>
                        <div>
                            <label for="email" class="block text-sm font-medium text-gray-700">
                                "Email address"
                            </label>
                            <input
                                id="email"
                                name="email"
                                type="email"
                                required
                                class="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                                placeholder="Email address"
                                prop:value=move || email.get()
                                on:input=move |ev| set_email.set(event_target_value(&ev))
                            />
                        </div>
                        
                        <div>
                            <label for="password" class="block text-sm font-medium text-gray-700">
                                "Password"
                            </label>
                            <input
                                id="password"
                                name="password"
                                type="password"
                                required
                                class="mt-1 appearance-none relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
                                placeholder="Password"
                                prop:value=move || password.get()
                                on:input=move |ev| set_password.set(event_target_value(&ev))
                            />
                        </div>
                        
                        {move || error.get().map(|err| view! {
                            <div class="rounded-md bg-red-50 p-4">
                                <div class="flex">
                                    <div class="ml-3">
                                        <h3 class="text-sm font-medium text-red-800">
                                            {err}
                                        </h3>
                                    </div>
                                </div>
                            </div>
                        })}
                        
                        <div>
                            <button
                                type="submit"
                                disabled=move || loading.get()
                                class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {move || if loading.get() {
                                    view! {
                                        <span class="flex items-center">
                                            <svg class="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                            </svg>
                                            "Signing in..."
                                        </span>
                                    }.into_any()
                                } else {
                                    view! { "Sign in" }.into_any()
                                }}
                            </button>
                        </div>
                        
                        <div class="text-center">
                            <p class="text-sm text-gray-600">
                                "Demo credentials: admin@ghostcp.com / password"
                            </p>
                        </div>
                    </form>
                </Card>
            </div>
        </div>
    }
}