package com.forlixdev.ca;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class Subject {

    protected static final Logger LOG = LogManager.getLogger(Subject.class.getName());

    private final X500Name subject;

    private Subject(X500Name subject) {
        this.subject = subject;
    }

    public X500Name getX500Name() {
        return subject;
    }

    public static class Builder {
        private String commonName;
        private String organization;
        private String organizationalUnit;
        private String locality;
        private String state;
        private String country;
        private String email;
        private String postalCode;
        private String street;
        private String dnQualifier;
        private String title;
        private String serialNumber;
        private String pseudonym;
        private String businessCategory;
        private String roleOccupation;
        private String description;
        private String generationQualifier;
        private String givenName;
        
        public Builder commonName(String commonName) {
            this.commonName = commonName;
            return this;
        }

        public Builder organization(String organization) {
            this.organization = organization;
            return this;
        }

        public Builder organizationalUnit(String organizationalUnit) {
            this.organizationalUnit = organizationalUnit;
            return this;
        }

        public Builder locality(String locality) {
            this.locality = locality;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder country(String country) {
            this.country = country;
            return this;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public Builder postalCode(String postalCode) {
            this.postalCode = postalCode;
            return this;
        }

        public Builder street(String street) {
            this.street = street;
            return this;
        }

        public Builder dnQualifier(String dnQualifier) {
            this.dnQualifier = dnQualifier;
            return this;
        }

        public Builder title(String title) {
            this.title = title;
            return this;
        }

        public Builder serialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public Builder pseudonym(String pseudonym) {
            this.pseudonym = pseudonym;
            return this;
        }

        public Builder businessCategory(String businessCategory) {
            this.businessCategory = businessCategory;
            return this;
        }

        public Builder roleOccupation(String roleOccupation) {
            this.roleOccupation = roleOccupation;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder generationQualifier(String generationQualifier) {
            this.generationQualifier = generationQualifier;
            return this;
        }

        public Builder givenName(String givenName) {
            this.givenName = givenName;
            return this;
        }

        public Subject build() {
            X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
            if (commonName != null) builder.addRDN(BCStyle.CN, commonName);
            if (organization != null) builder.addRDN(BCStyle.O, organization);
            if (organizationalUnit != null) builder.addRDN(BCStyle.OU, organizationalUnit);
            if (locality != null) builder.addRDN(BCStyle.L, locality);
            if (state != null) builder.addRDN(BCStyle.ST, state);
            if (country != null) builder.addRDN(BCStyle.C, country);
            if (email != null) builder.addRDN(BCStyle.EmailAddress, email);
            if (postalCode != null) builder.addRDN(BCStyle.POSTAL_CODE, postalCode);
            if (street != null) builder.addRDN(BCStyle.STREET, street);
            if (dnQualifier != null) builder.addRDN(BCStyle.DN_QUALIFIER, dnQualifier);
            if (title != null) builder.addRDN(BCStyle.T, title);
            if (serialNumber != null) builder.addRDN(BCStyle.SERIALNUMBER, serialNumber);
            if (pseudonym != null) builder.addRDN(BCStyle.PSEUDONYM, pseudonym);
            if (businessCategory != null) builder.addRDN(BCStyle.BUSINESS_CATEGORY, businessCategory);
            if (roleOccupation != null) builder.addRDN(BCStyle.ROLE, roleOccupation);
            if (description != null) builder.addRDN(BCStyle.DESCRIPTION, description);
            if (generationQualifier != null) builder.addRDN(BCStyle.GENERATION, generationQualifier);
            if (givenName != null) builder.addRDN(BCStyle.GIVENNAME, givenName);

            return new Subject(builder.build());
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Parses a string representation of an X.500 Distinguished Name (DN) and constructs an X500Name object.
     * This method supports various standard DN components and logs any invalid keys encountered during parsing.
     *
     * @param subjectString A string representation of the X.500 Distinguished Name, with components separated by commas
     *                      and key-value pairs separated by '='. For example: "CN=John Doe,O=Example Inc,C=US"
     * @return An X500Name object representing the parsed Distinguished Name
     */
    public static X500Name parseSubjectString(String subjectString) {
        LOG.trace("Parsing subject string: {}", subjectString);
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        var parts = subjectString.split(",");
        for (var part : parts) {
            var keyValue = part.trim().split("=");
            if (keyValue.length == 2) {
                var key = keyValue[0].trim().toUpperCase();
                var value = keyValue[1].trim();
                switch (key) {
                    case "CN" -> builder.addRDN(BCStyle.CN, value);
                    case "O" -> builder.addRDN(BCStyle.O, value);
                    case "OU" -> builder.addRDN(BCStyle.OU, value);
                    case "L" -> builder.addRDN(BCStyle.L, value);
                    case "ST" -> builder.addRDN(BCStyle.ST, value);
                    case "C" -> builder.addRDN(BCStyle.C, value);
                    case "SERIALNUMBER" -> builder.addRDN(BCStyle.SERIALNUMBER, value);
                    case "BUSINESS_CATEGORY" -> builder.addRDN(BCStyle.BUSINESS_CATEGORY, value);
                    case "ROLEOCCUPATION" -> builder.addRDN(BCStyle.ROLE, value);
                    case "DESCRIPTION" -> builder.addRDN(BCStyle.DESCRIPTION, value);
                    case "POSTALCODE" -> builder.addRDN(BCStyle.POSTAL_CODE, value);
                    case "STREETADDRESS" -> builder.addRDN(BCStyle.STREET, value);
                    case "DNQUALIFIER" -> builder.addRDN(BCStyle.DN_QUALIFIER, value);
                    case "GN" -> builder.addRDN(BCStyle.GIVENNAME, value);
                    case "TELEPHONENUMBER" -> builder.addRDN(BCStyle.TELEPHONE_NUMBER, value);
                    case "SN" -> builder.addRDN(BCStyle.SURNAME, value);
                    //case "title" -> builder.addRDN(BCStyle., value); //??
                    case "EMAILADDRESS" -> builder.addRDN(BCStyle.EmailAddress, value);
                    case "PSEUDONYM" -> builder.addRDN(BCStyle.PSEUDONYM, value);
                    case "GENERATIONQUALIFIER" -> builder.addRDN(BCStyle.GENERATION, value);
                    default -> LOG.error("Invalid key: {}", key);
                }
            }
        }
        return builder.build();
    }


}