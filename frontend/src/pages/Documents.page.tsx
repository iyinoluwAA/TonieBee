import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Title,
  Text,
  Stack,
  Card,
  Group,
  Badge,
  Button,
  Loader,
  Center,
  SimpleGrid,
  Box,
  rem,
  Paper,
  ActionIcon,
} from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { IconFileText, IconDownload, IconEye, IconFile } from '@tabler/icons-react';
import { DarkLayout } from '../components/DarkLayout';
import { notifications } from '@mantine/notifications';

interface Document {
  id: string;
  document_type: string;
  file_name: string;
  file_url: string;
  file_size: number | null;
  uploaded_at: string;
  description: string | null;
}

export function DocumentsPage() {
  const navigate = useNavigate();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const [documents, setDocuments] = useState<Document[]>([]);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    fetchUser();
    fetchDocuments();
  }, []);

  async function fetchUser() {
    try {
      const resp = await fetch('/api/users/me', {
        credentials: 'include',
      });
      if (resp.status === 200) {
        const data = await resp.json();
        setUser(data.data.user);
      } else if (resp.status === 401) {
        navigate('/login');
      }
    } catch (error) {
      console.error('Error fetching user:', error);
    }
  }

  async function fetchDocuments() {
    try {
      const resp = await fetch('/api/documents', {
        credentials: 'include',
      });
      if (resp.status === 200) {
        const data = await resp.json();
        setDocuments(data.data || []);
      } else if (resp.status === 401) {
        navigate('/login');
      } else {
        notifications.show({
          title: 'Error',
          message: 'Failed to load documents',
          color: 'red',
        });
      }
    } catch (error) {
      console.error('Error fetching documents:', error);
      notifications.show({
        title: 'Error',
        message: 'Failed to connect to server',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }

  const formatFileSize = (bytes: number | null) => {
    if (!bytes) return 'Unknown size';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-CA', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  };

  const getFileIcon = (fileName: string) => {
    return <IconFile size={24} />;
  };

  const handleDownload = async (document: Document) => {
    try {
      // In a real app, this would download the file
      window.open(document.file_url, '_blank');
      notifications.show({
        title: 'Download Started',
        message: `Downloading ${document.file_name}`,
        color: 'green',
      });
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to download document',
        color: 'red',
      });
    }
  };

  if (loading) {
    return (
      <DarkLayout user={user} title="Documents">
        <Center h="60vh">
          <Loader size="lg" />
        </Center>
      </DarkLayout>
    );
  }

  return (
    <DarkLayout user={user} title="Documents">
      <Container size="xl" py="xl">
        <Stack gap="xl">
          {/* Header */}
          <Box>
            <Title order={1} size={isMobile ? rem(28) : rem(36)} mb="xs" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
              My Documents
            </Title>
            <Text size="lg" c="gray.2" style={{ textShadow: '0 1px 5px rgba(0, 0, 0, 0.2)' }}>
              Access and download your policy documents
            </Text>
          </Box>

          {/* Documents List */}
          {documents.length === 0 ? (
            <Paper
              p="xl"
              radius="lg"
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                borderColor: 'rgba(255, 255, 255, 0.1)',
                backdropFilter: 'blur(10px)',
              }}
              withBorder
            >
              <Stack align="center" gap="md">
                <IconFileText size={48} style={{ color: 'var(--mantine-color-gray-5)' }} />
                <Text size="lg" fw={500} c="white" ta="center">
                  No documents available
                </Text>
                <Text size="sm" c="gray.3" ta="center">
                  Your policy documents will appear here once available
                </Text>
              </Stack>
            </Paper>
          ) : (
            <SimpleGrid cols={{ base: 1, md: 2, lg: 3 }} spacing="md">
              {documents.map((document) => (
                <Card
                  key={document.id}
                  padding="lg"
                  radius="md"
                  withBorder
                  style={{
                    background: 'rgba(255, 255, 255, 0.05)',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    backdropFilter: 'blur(10px)',
                    transition: 'all 0.3s ease',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.transform = 'translateY(-4px)';
                    e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.transform = 'translateY(0)';
                    e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
                  }}
                >
                  <Stack gap="md">
                    <Group justify="space-between" align="flex-start">
                      <Box style={{ flex: 1 }}>
                        <Group gap="sm" mb={8}>
                          <Box style={{ color: 'var(--mantine-color-blue-4)' }}>
                            {getFileIcon(document.file_name)}
                          </Box>
                          <Text fw={700} size="md" c="white" style={{ textShadow: '0 1px 3px rgba(0, 0, 0, 0.3)' }} lineClamp={1}>
                            {document.file_name}
                          </Text>
                        </Group>
                        <Badge variant="light" color="blue" size="sm" mb={8}>
                          {document.document_type.replace('_', ' ').charAt(0).toUpperCase() + document.document_type.slice(1).replace('_', ' ')}
                        </Badge>
                        {document.description && (
                          <Text size="sm" c="gray.3" lineClamp={2} mb={8}>
                            {document.description}
                          </Text>
                        )}
                        <Text size="xs" c="gray.4">
                          {formatFileSize(document.file_size)} • {formatDate(document.uploaded_at)}
                        </Text>
                      </Box>
                    </Group>

                    <Group gap="xs" mt="md">
                      <Button
                        variant="light"
                        size="sm"
                        leftSection={<IconEye size={16} />}
                        onClick={() => window.open(document.file_url, '_blank')}
                        style={{ flex: 1 }}
                      >
                        View
                      </Button>
                      <Button
                        variant="light"
                        size="sm"
                        leftSection={<IconDownload size={16} />}
                        onClick={() => handleDownload(document)}
                        style={{ flex: 1 }}
                      >
                        Download
                      </Button>
                    </Group>
                  </Stack>
                </Card>
              ))}
            </SimpleGrid>
          )}
        </Stack>
      </Container>
    </DarkLayout>
  );
}

