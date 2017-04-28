<?php

namespace samkoch\yii2ldap;

use yii\base\Component;
use yii\base\InvalidConfigException;

class Ldap extends Component
{
    public $config;
    public $baseDn;
    protected $ldapLink;
    protected $data = array();

    public function init()
    {
        foreach (['host', 'port', 'baseDn', 'username', 'password'] as $configItem) {
            if (empty($this->config[$configItem])) {
                throw new InvalidConfigException('LDAP::' . $configItem . ' cannot be empty.');
            }
        }

        try {
            $this->ldapLink = ldap_connect($this->config['host'], $this->config['port']);
            ldap_bind($this->ldapLink, $this->config['username'], $this->config['password']);
            ldap_set_option($this->ldapLink, LDAP_OPT_PROTOCOL_VERSION, 3);
        } catch (Exception $e) {
            throw new Exception("LDAP: Cannot connect to $this->config['host']: $e->getMessage()");
        }

        if (isset($this->config['baseDn'])) {
            $this->baseDn = $this->config['baseDn'];
        }
    }
    
    public function validateUserCredentials($username, $password) {
        try {
            $this->ldapLink = ldap_connect($this->config['host'], $this->config['port']);
            return @ldap_bind($this->ldapLink, $username, $password);
        } catch (Exception $e) {
            throw new Exception("LDAP: Cannot connect to $this->config['host']: $e->getMessage()");
        }
    }

    public function getConnection()
    {
        return $this->ldapLink;
    }

    public function search($filter, $attributes)
    {
        return ldap_search($this->ldapLink, $this->baseDn, $filter, $attributes);
    }

    public function getEntries($filter, $attributes)
    {
        return ldap_get_entries($this->ldapLink, ldap_search($this->ldapLink, $this->baseDn, $filter, $attributes));
    }

    public function getEntriesForSearch($search)
    {
        return ldap_get_entries($this->ldapLink, $search);
    }

    public function getSingleValue($data, $attribute, $utf8encode = true)
    {
        $value = $data[0][$attribute][0];
        return $utf8encode ? utf8_encode($value) : $value;
    }

    public function getMultiValue($data, $attribute, $utf8encode = true)
    {
        $values = $data[0][$attribute];
        $res = [];
        foreach($values as $key => $value) {
            if($key !== 'count') {
                $res[] = $utf8encode ? utf8_encode($value) : $value;
            }
        }

        return $res;
    }


    /**
     * Shortcut function for getting groups and resolving it's users.
     *
     * @param string $filter
     * @param array $groupAttributes
     * @param array $rangeAttributes
     * @param array $userAttributes
     * @param array $memberFilterGroups
     * @param array $memberFilterUser
     */
    public function getResolvedUsers($filter, $groupAttributes, $rangeAttributes, $userAttributes, $memberFilterGroups, $memberFilterUser)
    {
        $this->getGroupsRecursive($filter, $groupAttributes, $rangeAttributes, $userAttributes, $memberFilterGroups, $memberFilterUser);
        return $this->resolveUsers($userAttributes, $groupAttributes);
    }


    /**
     * Retrieve groups from Active Directory.
     *
     * @param string $filter
     * @param array $attributes
     * @param array $rangeAttributes
     */
    public function getGroups($filter, $attributes, $rangeAttributes = array())
    {
        if ($res = ldap_search($this->ldapLink, $this->baseDn, $filter, array_merge($attributes, $rangeAttributes))) {
            $data = ldap_get_entries($this->ldapLink, $res);
            if ($data['count'] > 0) {
                unset($data['count']);

                //get paging data for range attributes
                //range attributes come in pages of 1500 entries, paging is only available in PHP > 5.4
                foreach ($data as $key => $group) {
                    if (count($rangeAttributes)) {
                        foreach ($rangeAttributes as $rangeAttribute) {
                            if (array_key_exists($rangeAttribute . ';range=0-1499', $group)) {
                                $data[$key][$rangeAttribute] = $group[$rangeAttribute . ';range=0-1499'];

                                //loop through pages
                                $position = 1500;
                                $lastPage = false;
                                while (!$lastPage) {
                                    $rangeAttributePage = $rangeAttribute . ';range=' . $position . '-' . ($position + 1499);
                                    $res = ldap_search($this->ldapLink, $this->baseDn, $filter, array($rangeAttributePage));
                                    $rangeAttributeData = ldap_get_entries($this->ldapLink, $res);

                                    $rangeAttributePageLast = $rangeAttribute . ';range=' . $position . '-*';
                                    //get next page
                                    if (array_key_exists($rangeAttributePage, $rangeAttributeData[0])) {
                                        $data[$key][$rangeAttribute] = array_merge($data[$key][$rangeAttribute], $rangeAttributeData[0][$rangeAttributePage]);
                                        $position += 1500;
                                    } //get last page and termine while loop
                                    elseif (array_key_exists($rangeAttributePageLast, $rangeAttributeData[0])) {
                                        $data[$key][$rangeAttribute] = array_merge($data[$key][$rangeAttribute],
                                          $rangeAttributeData[0][$rangeAttributePageLast]);
                                        $lastPage = true;
                                    }
                                }
                            }
                        }
                    }
                }

                return $data;
            }
        }
    }


    /**
     * Recursive function to retrieve all member groups.
     *
     * @param string $filter
     * @param array $groupAttributes
     * @param array $rangeAttributes
     * @param array $userAttributes
     * @param array $memberFilterGroups
     * @param array $memberFilterUser
     */
    public function getGroupsRecursive($filter, $groupAttributes, $rangeAttributes, $userAttributes, $memberFilterGroups, $memberFilterUser)
    {
        //check and add some mandatory attributes if necessary
        $mandatoryGroupAttributes = array('objectGUID', 'distinguishedName', 'managedBy', 'msExchCoManagedByLink');
        $groupAttributes = array_unique(array_merge($groupAttributes, $mandatoryGroupAttributes));

        $mandatoryRangeAttributes = array('member');
        $rangeAttributes = array_unique(array_merge($rangeAttributes, $mandatoryRangeAttributes));

        //retrieve groups
        $groups = $this->getGroups($filter, $groupAttributes, $rangeAttributes);
        if ($groups) {
            foreach ($groups as $key => $group) {
                $groupDistinguishedName = $group['distinguishedname'][0];

                //save group attribute values
                foreach ($groupAttributes as $groupAttribute) {
                    $value = $group[strtolower($groupAttribute)][0];

                    //objectGUID needs special processing
                    if ('objectGUID' == $groupAttribute) {
                        $value = $this->getGUID($group[strtolower($groupAttribute)][0]);
                    }

                    //store in class data array
                    $this->data[md5($groupDistinguishedName)][$groupAttribute] = $value;
                }

                //get all users from member attribute
                $users = $this->filterMember($group['member'], $memberFilterUser);

                //special case: add owner, as he is not listed among the attribute members
                $users[] = $group['managedby'][0];

                //special case: add co owners if set
                if (count($group['msexchcomanagedbylink'])) {
                    unset($group['msexchcomanagedbylink']['count']);
                    foreach ($group['msexchcomanagedbylink'] as $coManager) {
                        $users[] = $coManager;
                    }
                }

                if (count($users)) {
                    foreach ($users as $user) {
                        //skip already found users
                        if (isset($this->data[md5($groupDistinguishedName)]['users']) && array_key_exists(md5($user),
                            $this->data[md5($groupDistinguishedName)]['users'])
                        ) {
                            continue;
                        }

                        //get user attributes
                        $userData = $this->getUserAttributesByDistinguishedName($user, $userAttributes);

                        if($userData) {
                            //process and add them to class data array
                            $userAttributesValues = array();
                            foreach ($userAttributes as $userAttribute) {
                                $userAttributesValues[$userAttribute] = $userData[0][strtolower($userAttribute)][0];

                                //objectGUID needs special processing
                                if ('objectGUID' == $userAttribute) {
                                    $userAttributesValues[$userAttribute] = $this->getGUID($userData[0][strtolower($userAttribute)][0]);
                                }
                            }
                        }
                        $this->data[md5($groupDistinguishedName)]['users'][md5($user)] = $userAttributesValues;
                    }
                }

                //process groups of member attribute
                $membersGroups = $this->filterMember($group['member'], $memberFilterGroups);
                if (count($membersGroups)) {

                    foreach ($membersGroups as $membersGroup) {
                        //skip already found groups
                        if (array_key_exists(md5($membersGroup), $this->data)) {
                            continue;
                        }

                        //store parent group
                        $this->data[md5($membersGroup)]['parent'] = $groupDistinguishedName;

                        //call this fuction with the current member group recursive
                        $filter = '(&(objectClass=Group)(distinguishedName=' . $this->escapeFilterValue($membersGroup) . '))';
                        $this->getGroupsRecursive($filter, $groupAttributes, $rangeAttributes, $userAttributes, $memberFilterGroups,
                          $memberFilterUser);
                    }
                }
            }
        }
    }


    /**
     * Resolve users.
     * Can only be called after $this->data has been populated.
     *
     * @param array $userAttributes
     * @param array $groupAttributes
     */
    public function resolveUsers($userAttributes, $groupAttributes)
    {
        if (!is_array($this->data) || !count($this->data)) {
            return false;
        }

        $res = array();
        foreach ($this->data as $key => $data) {
            if (array_key_exists('users', $data)) {
                foreach ($data['users'] as $user) {

                    //skip user if no email address set
                    if (empty($user['mail'])) {
                        continue;
                    }

                    //get user attribute values
                    foreach ($userAttributes as $userAttribute) {
                        $res[md5($user['distinguishedName'])][$userAttribute] = $user[$userAttribute];
                    }

                    //get group attribute values
                    $groupAttributeValues = array();
                    foreach ($groupAttributes as $groupAttribute) {
                        $groupAttributeValues[$groupAttribute] = $data[$groupAttribute];
                    }
                    $res[md5($user['distinguishedName'])]['groups'][md5($data['distinguishedName'])] = $groupAttributeValues;

                    //climb up tree and get all groups a user belongs to
                    $parent = $data['parent'];
                    while (isset($parent) && array_key_exists(md5($parent), $this->data)) {
                        $hashParent = md5($parent);

                        //get group attribute values
                        $groupAttributeValues = array();
                        foreach ($groupAttributes as $groupAttribute) {
                            $groupAttributeValues[$groupAttribute] = $this->data[$hashParent][$groupAttribute];
                        }
                        $res[md5($user['distinguishedName'])]['groups'][md5($this->data[$hashParent]['distinguishedName'])] = $groupAttributeValues;

                        //get next parent
                        $parent = $this->data[$hashParent]['parent'];
                    }
                }
            }
        }

        return $res;
    }


    /**
     * Convert GUID to usable string.
     * See https://github.com/Alaneor/AD-X/blob/master/ADX/Core/Converter.php#L263
     *
     * @param mixed $guid
     */
    public function getGuid($guid)
    {
        $hex_guid = unpack("H*hex", $guid);
        $hex = $hex_guid["hex"];
        $hex1 = substr($hex, -26, 2) . substr($hex, -28, 2) . substr($hex, -30, 2) . substr($hex, -32, 2);
        $hex2 = substr($hex, -22, 2) . substr($hex, -24, 2);
        $hex3 = substr($hex, -18, 2) . substr($hex, -20, 2);
        $hex4 = substr($hex, -16, 4);
        $hex5 = substr($hex, -12, 12);
        $guid = $hex1 . "-" . $hex2 . "-" . $hex3 . "-" . $hex4 . "-" . $hex5;

        return $guid;
    }

    public function setGuid($guid)
    {
        $guid = str_replace('-', '', $guid);
        $octet_str = substr($guid, 6, 2);
        $octet_str .= substr($guid, 4, 2);
        $octet_str .= substr($guid, 2, 2);
        $octet_str .= substr($guid, 0, 2);
        $octet_str .= substr($guid, 10, 2);
        $octet_str .= substr($guid, 8, 2);
        $octet_str .= substr($guid, 14, 2);
        $octet_str .= substr($guid, 12, 2);
        $octet_str .= substr($guid, 16, strlen($guid));
        $hex_guid = '';
        for ($i = 0; $i <= strlen($octet_str) - 2; $i = $i + 2) {
            $hex_guid .= "\\" . substr($octet_str, $i, 2);
        }
        return $hex_guid;
    }


    /**
     * Filter items in members attribute.
     *
     * @param array $members
     * @param array $filters
     */
    public function filterMember(
      $members,
      $filters = array()
    ) {
        if (is_array($members)) {
            $res = array();
            //remote count attribute
            if (array_key_exists('count', $members)) {
                unset($members['count']);
            }

            //loop through filters
            if (is_array($filters) && count($filters) > 0) {
                //loop through members
                foreach ($members as $key => $member) {

                    $filterRes = array();
                    foreach ($filters as $filter) {
                        switch ($filter['type']) {
                            case 'OR':
                                $found = false;
                                if (is_array($filter['value'])) {
                                    foreach ($filter['value'] as $value) {
                                        if (stripos($member, $value) !== false) {
                                            $found = true;
                                        }
                                    }
                                } else {
                                    if (stripos($member, $filter) !== false) {
                                        $found = true;
                                    }
                                }
                                $filterRes[] = $found;
                                break;

                            case 'AND':
                            default:
                                $match = true;
                                if (is_array($filter['value'])) {
                                    foreach ($filter['value'] as $value) {
                                        if (stripos($member, $value) === false) {
                                            $match = false;
                                        }
                                    }
                                } else {
                                    if (stripos($member, $filter['value']) === false) {
                                        $match = false;
                                    }
                                }
                                $filterRes[] = $match;
                                break;
                        }
                    }

                    //only add member to result list if all condition matched
                    if (array_search(false, $filterRes) === false) {
                        $res[$key] = $member;
                    }
                }
            } else {
                $res = $members;
            }

            return $res;
        }
    }

    /**
     * Escape values for use in LDAP filters.
     *
     * @param string $s
     */
    public static function escapeFilterValue($s)
    {
        return str_replace(array('(', ')', '\\,'), array('\28', '\29', '\\\\,'), $s);
    }

    /**
     * Get user attributes by user distinguishedName.
     *
     * @param string $distinguishedName
     * @param array $attributes
     * @return array|boolean
     */
    public function getUserAttributesByDistinguishedName($distinguishedName, $attributes) {
        return $this->getUserAttributesByIdUserAttribute('distinguishedName', $distinguishedName, $attributes);
    }

    /**
     * Get user attributes by sAMAccountName.
     *
     * @param string $distinguishedName
     * @param array $attributes
     * @return array|boolean
     */
    public function getUserAttributesBySAMAccountName($sAMAccountName, $attributes) {
        return $this->getUserAttributesByIdUserAttribute('sAMAccountName', $sAMAccountName, $attributes);
    }

    /**
     * Get user attributes by email.
     *
     * @param string $distinguishedName
     * @param array $attributes
     * @return array|boolean
     */
    public function getUserAttributesByEmail($email, $attributes) {
        return $this->getUserAttributesByIdUserAttribute('mail', $email, $attributes);
    }

    /**
     * Get user attributes by id user attribute.
     *
     * @param string $distinguishedName
     * @param array $attributes
     * @return array|boolean
     */
    protected function getUserAttributesByIdUserAttribute($idUserAttributeName, $idUserAttributeValue, $attributes) {
        if(!is_array($attributes)) {
            $singleAttribute = $attributes;
            $attributes = [];
            $attributes[] = $singleAttribute;
        }

        $filter = "(&(objectClass=User)(".$idUserAttributeName."=" . $this->escapeFilterValue($idUserAttributeValue) . "))";
        if ($res = ldap_search($this->ldapLink, $this->baseDn, $filter, $attributes)) {
            $data = ldap_get_entries($this->ldapLink, $res);
            if ($data['count'] == 1) {
                if(isset($singleAttribute)) {
                    return $data[0][strtolower($singleAttribute)][0];
                }
                return $data;
            }
        }
    }

}
