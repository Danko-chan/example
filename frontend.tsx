"use client"
import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { loginUser } from '@/utils/api';
import { useAuth } from '@/context/authContext';
import Cookies from 'js-cookie';
import CryptoJS from 'crypto-js';

const LoginPage: React.FC = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });

  const [error, setError] = useState(null);
  const router = useRouter();
  const { setUsername, setAuthStatus } = useAuth();

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const response = await loginUser(formData);

      const encryptedSessionData = Cookies.get('user_session');
      const ivHex = Cookies.get('user_session_iv');
      const encryptionKey = process.env.KEY; //i am also having problem here when using env variable it is returning undefined
    //so i tried directly giving it the key it worked but got error during decryptedSessionData
      
        try {

          // Convert IV from hexadecimal string to buffer
          const iv = Buffer.from(ivHex, 'hex');

          // Decrypt session data using the IV
          const bytes = CryptoJS.AES.decrypt(encryptedSessionData, encryptionKey, {
            iv: CryptoJS.enc.Hex.parse(iv.toString('hex')), 
          });
          const decryptedSessionData = bytes.toString(CryptoJS.enc.Utf8);
          console.log({'decrypt':decryptedSessionData})
          
          if (decryptedSessionData) {
            try {
              const session = JSON.parse(decryptedSessionData);
              console.log('Decrypted Session Data:', session);
     
            } catch (error) {
              console.error('JSON Parsing Error:', error);
             
            }
          } else {
            console.error('Decrypted Session Data is empty or invalid.');
            // Handle empty or invalid data here
          }
                
      
         
          console.log('Login successful:', response);
          // Redirect to a protected route or dashboard
          router.push('/');
        } catch (error) {
          console.error('Decryption Error:', error);
          // Handle the decryption error
        }
       
      console.log('Encrypted Session Data:', encryptedSessionData);
      console.log('Encryption Key:', encryptionKey);

    } catch (err:any) {
      setError(err.message || 'Login failed');
    }
  };

  return (
    <div>
      <h1>User Login</h1>
      <form onSubmit={handleSubmit}>
        <div>
          <label>Email:</label>
          <input
          className='text-black'
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
          />
        </div>
        <div>
          <label>Password:</label>
          <input
          className='text-black'
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
          />
        </div>
        <button type="submit">Login</button>
        {error && <div className="error">{error}</div>}
      </form>
    </div>
  );
};

export default LoginPage;
