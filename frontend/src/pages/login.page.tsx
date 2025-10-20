import {AuthenticationForm } from '../AuthenticationForm/AuthenticationForm';
import { ActionToggle } from '@/components/ColorSchemeToggle/ActionToggle';
export function LoginPage() {
  return (
    <>
      <AuthenticationForm />
      <ActionToggle />
    </>
  );
}