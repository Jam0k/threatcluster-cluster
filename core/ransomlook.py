#!/usr/bin/env python3
"""
RansomLook API Client
Fetches ransomware group data from RansomLook API
"""

import json
import logging
import aiohttp
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class RansomLookClient:
    """Client for interacting with RansomLook API"""
    
    BASE_URL = "https://www.ransomlook.io/api"
    
    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def get_groups(self) -> List[str]:
        """Get list of all ransomware groups"""
        if not self.session:
            raise RuntimeError("Client session not initialized")
        
        url = f"{self.BASE_URL}/groups"
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status} when fetching groups")
                
                groups = await response.json()
                logger.info(f"Fetched {len(groups)} ransomware groups from RansomLook")
                return groups
                
        except Exception as e:
            logger.error(f"Failed to fetch groups from RansomLook: {e}")
            raise
    
    async def get_group_details(self, group_name: str) -> Dict[str, Any]:
        """Get detailed information about a specific group"""
        if not self.session:
            raise RuntimeError("Client session not initialized")
        
        url = f"{self.BASE_URL}/group/{group_name}"
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    raise Exception(f"HTTP {response.status} when fetching group details for {group_name}")
                
                details = await response.json()
                
                # Clean up the details by removing screen and source fields
                cleaned_details = self._clean_details(details)
                
                return cleaned_details
                
        except Exception as e:
            logger.error(f"Failed to fetch details for group {group_name}: {e}")
            raise
    
    def _clean_details(self, data: Any) -> Any:
        """Recursively remove 'screen' and 'source' fields from the data"""
        if isinstance(data, dict):
            # Create a new dict without screen and source keys
            cleaned = {}
            for key, value in data.items():
                if key not in ('screen', 'source'):
                    cleaned[key] = self._clean_details(value)
            return cleaned
        elif isinstance(data, list):
            # Recursively clean items in lists
            return [self._clean_details(item) for item in data]
        else:
            # Return other types as-is
            return data
    
    async def get_all_groups_with_details(self) -> List[Dict[str, Any]]:
        """Get all groups with their detailed information"""
        groups = await self.get_groups()
        results = []
        
        for group_name in groups:
            try:
                details = await self.get_group_details(group_name)
                results.append({
                    'name': group_name,
                    'details': details
                })
            except Exception as e:
                logger.warning(f"Failed to get details for {group_name}: {e}")
                # Still include the group even if we can't get details
                results.append({
                    'name': group_name,
                    'details': None
                })
        
        return results