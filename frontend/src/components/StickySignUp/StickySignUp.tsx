import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Box, Group, Text, Button, ActionIcon } from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { IconX, IconArrowRight } from '@tabler/icons-react';

export function StickySignUp() {
  const navigate = useNavigate();
  const [visible, setVisible] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const isMobile = useMediaQuery('(max-width: 768px)');

  useEffect(() => {
    const handleScroll = () => {
      // Show after scrolling 300px
      if (window.scrollY > 300 && !dismissed) {
        setVisible(true);
      } else if (window.scrollY <= 300) {
        setVisible(false);
      }
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [dismissed]);

  if (!visible || dismissed) return null;

  return (
    <Box
      style={{
        position: 'fixed',
        bottom: 0,
        left: 0,
        right: 0,
        zIndex: 999,
        padding: isMobile ? '0.75rem' : '1rem',
        background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
        boxShadow: '0 -4px 20px rgba(0, 0, 0, 0.15)',
        animation: 'slideUp 0.3s ease-out',
      }}
    >
      <style>{`
        @keyframes slideUp {
          from {
            transform: translateY(100%);
            opacity: 0;
          }
          to {
            transform: translateY(0);
            opacity: 1;
          }
        }
      `}</style>
      
      <Group justify="space-between" wrap="nowrap" gap="md">
        <Group gap="md" wrap="nowrap" style={{ flex: 1 }}>
          <Text
            c="white"
            fw={600}
            size={isMobile ? 'sm' : 'md'}
            style={{ flex: 1 }}
          >
            {isMobile 
              ? 'Sign up for free access!' 
              : 'Sign up for free to access all features and get your personalized quote!'}
          </Text>
        </Group>
        
        <Group gap="sm" wrap="nowrap">
          <Button
            size={isMobile ? 'sm' : 'md'}
            variant="white"
            color="dark"
            radius="xl"
            rightSection={<IconArrowRight size={16} />}
            onClick={() => navigate('/register')}
          >
            {isMobile ? 'Sign Up' : 'Sign Up Free'}
          </Button>
          
          <ActionIcon
            variant="subtle"
            color="white"
            onClick={() => setDismissed(true)}
            aria-label="Dismiss"
          >
            <IconX size={18} />
          </ActionIcon>
        </Group>
      </Group>
    </Box>
  );
}



