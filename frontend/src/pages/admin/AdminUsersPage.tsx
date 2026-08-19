import { useEffect, useState } from 'react';
import {
  Table,
  Text,
  Paper,
  Group,
  Badge,
  ActionIcon,
  Select,
  TextInput,
  Button,
  Pagination,
  Modal,
  Stack,
  Title,
  Loader,
  Center,
  Alert,
  Divider,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconEdit, IconTrash, IconSearch, IconAlertCircle, IconPlus, IconShield, IconInfoCircle } from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';

interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  verified: boolean;
  twoFactorEnabled?: boolean;
  createdAt: string;
  updatedAt: string;
}

export function AdminUsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalUsers, setTotalUsers] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [roleModalOpened, { open: openRoleModal, close: closeRoleModal }] = useDisclosure(false);
  const [createModalOpened, { open: openCreateModal, close: closeCreateModal }] = useDisclosure(false);
  const [deleteModalOpened, { open: openDeleteModal, close: closeDeleteModal }] = useDisclosure(false);
  const [twoFAModalOpened, { open: open2FAModal, close: close2FAModal }] = useDisclosure(false);
  const [newRole, setNewRole] = useState<string>('user');
  const [updating, setUpdating] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [creating, setCreating] = useState(false);
  const [recoveryStatus, setRecoveryStatus] = useState<any>(null);
  const [loading2FA, setLoading2FA] = useState(false);
  const [resetting2FA, setResetting2FA] = useState(false);
  const limit = 10;
  
  const createForm = useForm({
    initialValues: {
      name: '',
      email: '',
      password: '',
      role: 'user' as string,
    },
    validate: {
      name: (val) => (val.length < 1 ? 'Name is required' : null),
      email: (val) => (/^\S+@\S+$/.test(val) ? null : 'Invalid email'),
      password: (val) => (val.length < 6 ? 'Password must be at least 6 characters' : null),
    },
  });

  useEffect(() => {
    fetchUsers();
  }, [page]);

  async function fetchUsers() {
    setLoading(true);
    try {
      const resp = await fetch(`/api/users/users?page=${page}&limit=${limit}`, {
        credentials: 'include',
      });

      if (resp.ok) {
        const data = await resp.json();
        setUsers(data.users || []);
        setTotalUsers(data.results || 0);
      } else {
        notifications.show({
          title: 'Error',
          message: 'Failed to fetch users',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error fetching users:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to fetch users',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }

  function getCsrfToken(): string | null {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrf_token') {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  async function handleRoleUpdate() {
    if (!selectedUser) return;

    setUpdating(true);
    try {
      const csrfToken = getCsrfToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      console.log('Updating role:', { user_id: selectedUser.id, role: newRole });
      
      const resp = await fetch('/api/users/role', {
        method: 'PUT',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          user_id: selectedUser.id,
          role: newRole.toLowerCase(), // Ensure lowercase to match enum
        }),
      });
      
      console.log('Role update response status:', resp.status);

      if (resp.ok) {
        notifications.show({
          title: 'Success',
          message: `User role updated to ${newRole}`,
          color: 'green',
        });
        closeRoleModal();
        fetchUsers();
      } else {
        let errorMessage = 'Failed to update user role';
        try {
          const data = await resp.json();
          console.log('Error response:', data);
          errorMessage = data.message || data.error || JSON.stringify(data) || errorMessage;
        } catch (e) {
          // Response is not JSON, try to get text
          try {
            const text = await resp.text();
            console.log('Error response (text):', text);
            errorMessage = text || errorMessage;
          } catch (textErr) {
            console.error('Failed to parse error response:', textErr);
            // Ignore text parsing errors
          }
        }
        
        notifications.show({
          title: 'Error',
          message: errorMessage,
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error updating role:', err);
      notifications.show({
        title: 'Error',
        message: err instanceof Error ? err.message : 'Failed to update user role',
        color: 'red',
      });
    } finally {
      setUpdating(false);
    }
  }

  function handleEditRole(user: User) {
    setSelectedUser(user);
    setNewRole(user.role.toLowerCase()); // Ensure lowercase
    openRoleModal();
  }

  async function handleDeleteUser() {
    if (!selectedUser) return;

    setDeleting(true);
    try {
      const resp = await fetch(`/api/users/users/${selectedUser.id}`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (resp.ok) {
        notifications.show({
          title: 'Success',
          message: 'User deleted successfully',
          color: 'green',
        });
        closeDeleteModal();
        fetchUsers();
      } else {
        const data = await resp.json();
        notifications.show({
          title: 'Error',
          message: data.message || 'Failed to delete user',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error deleting user:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to delete user',
        color: 'red',
      });
    } finally {
      setDeleting(false);
    }
  }

  function handleDeleteClick(user: User) {
    setSelectedUser(user);
    openDeleteModal();
  }

  async function handleView2FAStatus(user: User) {
    setSelectedUser(user);
    setLoading2FA(true);
    setRecoveryStatus(null);
    open2FAModal();
    
    try {
      const resp = await fetch(`/api/2fa/admin/status/${user.id}`, {
        credentials: 'include',
      });

      if (resp.ok) {
        const data = await resp.json();
        setRecoveryStatus(data);
      } else {
        const errorData = await resp.json().catch(() => ({ message: 'Failed to fetch 2FA status' }));
        notifications.show({
          title: 'Error',
          message: errorData.message || 'Failed to fetch 2FA status',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error fetching 2FA status:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to fetch 2FA status',
        color: 'red',
      });
    } finally {
      setLoading2FA(false);
    }
  }

  async function handleReset2FA() {
    if (!selectedUser) return;
    
    setResetting2FA(true);
    try {
      const csrfToken = getCsrfToken();
      const resp = await fetch(`/api/2fa/admin/reset/${selectedUser.id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken || '',
        },
        credentials: 'include',
        body: JSON.stringify({}),
      });

      if (resp.ok) {
        const data = await resp.json();
        notifications.show({
          title: 'Success',
          message: data.message || '2FA has been reset for this user',
          color: 'green',
        });
        close2FAModal();
        fetchUsers(); // Refresh user list
      } else {
        const errorData = await resp.json().catch(() => ({ message: 'Failed to reset 2FA' }));
        notifications.show({
          title: 'Error',
          message: errorData.message || 'Failed to reset 2FA',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error resetting 2FA:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to reset 2FA',
        color: 'red',
      });
    } finally {
      setResetting2FA(false);
    }
  }

  async function handleCreateUser(values: typeof createForm.values) {
    setCreating(true);
    try {
      const resp = await fetch('/api/users/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          name: values.name,
          email: values.email,
          password: values.password,
          role: values.role,
        }),
      });

      if (resp.ok) {
        notifications.show({
          title: 'Success',
          message: 'User created successfully',
          color: 'green',
        });
        closeCreateModal();
        createForm.reset();
        fetchUsers();
      } else {
        const data = await resp.json();
        notifications.show({
          title: 'Error',
          message: data.message || 'Failed to create user',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error creating user:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to create user',
        color: 'red',
      });
    } finally {
      setCreating(false);
    }
  }

  const filteredUsers = users.filter(
    (user) =>
      user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const rows = filteredUsers.map((user) => (
    <Table.Tr key={user.id}>
      <Table.Td>
        <Text fw={500}>{user.name}</Text>
        <Text size="xs" c="dimmed">
          {user.email}
        </Text>
      </Table.Td>
      <Table.Td>
        <Badge color={user.role === 'admin' ? 'red' : 'blue'} variant="light">
          {user.role}
        </Badge>
      </Table.Td>
      <Table.Td>
        <Group gap="xs">
          {user.verified ? (
            <Badge color="green" variant="light">
              Verified
            </Badge>
          ) : (
            <Badge color="orange" variant="light">
              Unverified
            </Badge>
          )}
          {user.twoFactorEnabled && (
            <Badge color="blue" variant="light">
              2FA
            </Badge>
          )}
        </Group>
      </Table.Td>
      <Table.Td>
        <Text size="sm" c="dimmed">
          {new Date(user.createdAt).toLocaleDateString()}
        </Text>
      </Table.Td>
      <Table.Td>
        <Group gap="xs">
          <ActionIcon
            variant="light"
            color="blue"
            onClick={() => handleEditRole(user)}
            title="Edit Role"
          >
            <IconEdit size={16} />
          </ActionIcon>
          {user.twoFactorEnabled && (
            <ActionIcon
              variant="light"
              color="purple"
              onClick={() => handleView2FAStatus(user)}
              title="View 2FA Status"
            >
              <IconShield size={16} />
            </ActionIcon>
          )}
          <ActionIcon
            variant="light"
            color="red"
            onClick={() => handleDeleteClick(user)}
            title="Delete User"
          >
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
      </Table.Td>
    </Table.Tr>
  ));

  if (loading) {
    return (
      <Center h={400}>
        <Loader size="lg" />
      </Center>
    );
  }

  return (
    <div>
      <Group justify="space-between" mb="lg">
        <Title order={2}>User Management</Title>
        <Button leftSection={<IconPlus size={16} />} onClick={openCreateModal}>
          Add User
        </Button>
      </Group>

      <Paper withBorder p="md" mb="md">
        <Group justify="space-between" mb="md">
          <TextInput
            placeholder="Search users..."
            leftSection={<IconSearch size={16} />}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.currentTarget.value)}
            style={{ flex: 1, maxWidth: 400 }}
          />
          <Text size="sm" c="dimmed">
            Total: {totalUsers} users
          </Text>
        </Group>

        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>User</Table.Th>
              <Table.Th>Role</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Joined</Table.Th>
              <Table.Th>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.length > 0 ? (
              rows
            ) : (
              <Table.Tr>
                <Table.Td colSpan={5}>
                  <Center p="xl">
                    <Text c="dimmed">No users found</Text>
                  </Center>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>

        {totalUsers > limit && (
          <Group justify="center" mt="md">
            <Pagination
              value={page}
              onChange={setPage}
              total={Math.ceil(totalUsers / limit)}
            />
          </Group>
        )}
      </Paper>

      <Modal
        opened={roleModalOpened}
        onClose={closeRoleModal}
        title="Update User Role"
      >
        <Stack>
          <Alert icon={<IconAlertCircle size={16} />} color="yellow">
            Changing a user's role will affect their access permissions immediately.
          </Alert>
          {selectedUser && (
            <>
              <Text>
                <strong>User:</strong> {selectedUser.name} ({selectedUser.email})
              </Text>
              <Select
                label="New Role"
                data={[
                  { value: 'user', label: 'User' },
                  { value: 'admin', label: 'Admin' },
                ]}
                value={newRole}
                onChange={(value) => value && setNewRole(value)}
              />
              <Group justify="flex-end" mt="md">
                <Button variant="subtle" onClick={closeRoleModal}>
                  Cancel
                </Button>
                <Button onClick={handleRoleUpdate} loading={updating}>
                  Update Role
                </Button>
              </Group>
            </>
          )}
        </Stack>
      </Modal>

      <Modal
        opened={deleteModalOpened}
        onClose={closeDeleteModal}
        title="Delete User"
      >
        <Stack>
          <Alert icon={<IconAlertCircle size={16} />} color="red">
            Are you sure you want to delete this user? This action cannot be undone.
          </Alert>
          {selectedUser && (
            <>
              <Text>
                <strong>User:</strong> {selectedUser.name} ({selectedUser.email})
              </Text>
              <Group justify="flex-end" mt="md">
                <Button variant="subtle" onClick={closeDeleteModal}>
                  Cancel
                </Button>
                <Button color="red" onClick={handleDeleteUser} loading={deleting}>
                  Delete User
                </Button>
              </Group>
            </>
          )}
        </Stack>
      </Modal>

      <Modal
        opened={createModalOpened}
        onClose={closeCreateModal}
        title="Create New User"
      >
        <form onSubmit={createForm.onSubmit(handleCreateUser)}>
          <Stack>
            <TextInput
              label="Name"
              placeholder="John Doe"
              required
              {...createForm.getInputProps('name')}
            />
            <TextInput
              label="Email"
              placeholder="user@example.com"
              required
              {...createForm.getInputProps('email')}
            />
            <TextInput
              label="Password"
              type="password"
              placeholder="Enter password"
              required
              {...createForm.getInputProps('password')}
            />
            <Select
              label="Role"
              data={[
                { value: 'user', label: 'User' },
                { value: 'admin', label: 'Admin' },
              ]}
              {...createForm.getInputProps('role')}
            />
            <Group justify="flex-end" mt="md">
              <Button variant="subtle" onClick={closeCreateModal}>
                Cancel
              </Button>
              <Button type="submit" loading={creating}>
                Create User
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      <Modal
        opened={twoFAModalOpened}
        onClose={close2FAModal}
        title="2FA Management"
        size="lg"
      >
        <Stack>
          {selectedUser && (
            <>
              <Alert icon={<IconInfoCircle size={16} />} color="blue">
                <Text size="sm">
                  <strong>User:</strong> {selectedUser.name} ({selectedUser.email})
                </Text>
              </Alert>

              {loading2FA ? (
                <Center p="xl">
                  <Loader size="md" />
                </Center>
              ) : recoveryStatus ? (
                <>
                  <Paper p="md" withBorder>
                    <Stack gap="sm">
                      <Group justify="space-between">
                        <Text fw={500}>2FA Status</Text>
                        <Badge color={recoveryStatus.two_factor_enabled ? 'green' : 'gray'}>
                          {recoveryStatus.two_factor_enabled ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </Group>

                      {recoveryStatus.two_factor_enabled && (
                        <>
                          <Divider />
                          <Group justify="space-between">
                            <Text size="sm">Total Recovery Codes</Text>
                            <Text fw={500}>{recoveryStatus.total_codes}</Text>
                          </Group>
                          <Group justify="space-between">
                            <Text size="sm">Unused Codes</Text>
                            <Badge color={recoveryStatus.unused_codes > 0 ? 'green' : 'red'}>
                              {recoveryStatus.unused_codes}
                            </Badge>
                          </Group>
                          <Group justify="space-between">
                            <Text size="sm">Used Codes</Text>
                            <Text>{recoveryStatus.used_codes}</Text>
                          </Group>
                          {recoveryStatus.days_until_expiration !== null && (
                            <>
                              <Divider />
                              <Group justify="space-between">
                                <Text size="sm">Days Until Expiration</Text>
                                <Badge
                                  color={
                                    recoveryStatus.days_until_expiration > 30
                                      ? 'green'
                                      : recoveryStatus.days_until_expiration > 7
                                      ? 'yellow'
                                      : 'red'
                                  }
                                >
                                  {recoveryStatus.days_until_expiration} days
                                </Badge>
                              </Group>
                            </>
                          )}
                        </>
                      )}
                    </Stack>
                  </Paper>

                  {recoveryStatus.two_factor_enabled && (
                    <Alert icon={<IconAlertCircle size={16} />} color="orange">
                      <Text size="sm">
                        <strong>Warning:</strong> Resetting 2FA will disable it and delete all recovery codes.
                        The user will need to set up 2FA again on their next login.
                      </Text>
                    </Alert>
                  )}

                  <Group justify="flex-end" mt="md">
                    <Button variant="subtle" onClick={close2FAModal}>
                      Close
                    </Button>
                    {recoveryStatus.two_factor_enabled && (
                      <Button
                        color="red"
                        onClick={handleReset2FA}
                        loading={resetting2FA}
                        leftSection={<IconShield size={16} />}
                      >
                        Reset 2FA
                      </Button>
                    )}
                  </Group>
                </>
              ) : (
                <Alert color="red">
                  <Text size="sm">Failed to load 2FA status</Text>
                </Alert>
              )}
            </>
          )}
        </Stack>
      </Modal>
    </div>
  );
}

