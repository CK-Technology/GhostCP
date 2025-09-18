use leptos::*;

#[component]
pub fn Footer() -> impl IntoView {
    view! {
        <footer class="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-auto">
            <div class="container mx-auto px-4 py-6">
                <div class="flex flex-col md:flex-row justify-between items-center">
                    <div class="flex items-center space-x-4 text-sm text-gray-600 dark:text-gray-400">
                        <span>"© 2024 GhostCP"</span>
                        <span>"•"</span>
                        <span>"v0.1.0"</span>
                        <span>"•"</span>
                        <span>"Port :2083"</span>
                    </div>

                    <div class="flex items-center space-x-6 mt-4 md:mt-0">
                        <a href="/docs" class="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white">
                            "Documentation"
                        </a>
                        <a href="/support" class="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white">
                            "Support"
                        </a>
                        <div class="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-400">
                            <div class="w-2 h-2 bg-green-500 rounded-full"></div>
                            <span>"System: Online"</span>
                        </div>
                    </div>
                </div>
            </div>
        </footer>
    }
}