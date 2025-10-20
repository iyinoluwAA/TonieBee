import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import { LoginPage } from './pages/login.page';
import { DashboardPage } from './pages/Dashboard.page';

const router = createBrowserRouter([
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/dashboard',
    element: <DashboardPage />,
  },
]);

export function Router() {
  return <RouterProvider router={router} />;
}
