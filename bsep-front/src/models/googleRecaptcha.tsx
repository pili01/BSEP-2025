declare module 'react-google-recaptcha' {
  import * as React from 'react';

  export interface ReCAPTCHAProps {
    sitekey: string;
    onChange?: (token: string | null) => void;
    onExpired?: () => void;
    onErrored?: () => void;
    theme?: 'light' | 'dark';
    size?: 'compact' | 'normal' | 'invisible';
    tabindex?: number;
    badge?: 'bottomright' | 'inline' | 'bottomleft';
    hl?: string;
    ref?: React.Ref<any>;
  }

  export default class ReCAPTCHA extends React.Component<ReCAPTCHAProps> {}
}