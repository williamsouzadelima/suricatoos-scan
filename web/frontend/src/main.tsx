import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import * as Tooltip from '@radix-ui/react-tooltip'
import App from './App'
import { ToastProvider } from './components/ui/Toast'
import './index.css'

const queryClient = new QueryClient()

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <Tooltip.Provider delayDuration={200}>
        <ToastProvider>
          <App />
        </ToastProvider>
      </Tooltip.Provider>
    </QueryClientProvider>
  </React.StrictMode>,
)
