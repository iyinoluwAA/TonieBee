import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom';
import { LoginPage } from './pages/login.page';
import { UserProfilePage } from './pages/UserProfile.page';
import { ClientPortalPage } from './pages/ClientPortal.page';
import { VerificationSuccessPage } from './pages/VerificationSuccess.page';
import { ForgotPasswordPage } from './pages/ForgotPassword.page';
import { ResetPasswordPage } from './pages/ResetPassword.page';
import { AdminDashboardPage } from './pages/AdminDashboard.page';
import { AdminLoginPage } from './pages/AdminLogin.page';
import { RecoverySetupPage } from './pages/RecoverySetup.page';
import { HomePage } from './pages/Home.page';
import { QuotePage } from './pages/Quote.page';
import { QuotesPage } from './pages/Quotes.page';
import { PoliciesPage } from './pages/Policies.page';
import { AppointmentsPage } from './pages/Appointments.page';
import { DocumentsPage } from './pages/Documents.page';
import { PaymentsPage } from './pages/Payments.page';
import { ClaimsPage } from './pages/Claims.page';

const router = createBrowserRouter([
  {
    path: '/',
    element: <HomePage />,
  },
  {
    path: '/home',
    element: <HomePage />,
  },
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/dashboard',
    element: <ClientPortalPage />,
  },
  {
    path: '/profile',
    element: <UserProfilePage />,
  },
  {
    path: '/verify-success',
    element: <VerificationSuccessPage />,
  },
  {
    path: '/forgot-password',
    element: <ForgotPasswordPage />,
  },
  {
    path: '/reset-password',
    element: <ResetPasswordPage />,
  },
  {
    path: '/admin/login',
    element: <AdminLoginPage />,
  },
  {
    path: '/recovery-setup',
    element: <RecoverySetupPage />,
  },
  {
    path: '/admin',
    element: <AdminDashboardPage />,
  },
  {
    path: '/admin/users',
    element: <AdminDashboardPage />,
  },
  {
    path: '/admin/data',
    element: <AdminDashboardPage />,
  },
  {
    path: '/admin/security',
    element: <AdminDashboardPage />,
  },
  {
    path: '/quote',
    element: <QuotePage />,
  },
  {
    path: '/quotes',
    element: <QuotesPage />,
  },
  {
    path: '/policies',
    element: <PoliciesPage />,
  },
  {
    path: '/appointments',
    element: <AppointmentsPage />,
  },
  {
    path: '/documents',
    element: <DocumentsPage />,
  },
  {
    path: '/payments',
    element: <PaymentsPage />,
  },
  {
    path: '/claims',
    element: <ClaimsPage />,
  },
  {
    path: '*',
    element: <Navigate to="/login" replace />,
  },
]);

export function Router() {
  return <RouterProvider router={router} />;
}
