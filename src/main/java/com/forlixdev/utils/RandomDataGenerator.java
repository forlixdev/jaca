package com.forlixdev.utils;

import java.util.Random;

/**
 * Utility class for generating random fields
 */
public class RandomDataGenerator {
   private static final String[] COMPANY_PREFIXES = {"Euro", "Continental", "Nordic", "Alpine", "Baltic", "Iberian", "Mediterranean", "Atlantic", "Central", "Eastern"};
   private static final String[] COMPANY_SUFFIXES = {"Solutions", "Systems", "Technologies", "Enterprises", "Innovations", "Group", "Industries", "Networks", "Labs", "Corporation"};
   private static final String[] CITIES = {"Paris", "Berlin", "Madrid", "Rome", "Amsterdam", "Vienna", "Stockholm", "Prague", "Warsaw", "Lisbon", "London", "New York", "Tokyo", "Sydney", "Melbourne", "Canberra", "Beijing", "Bojon"};
   private static final String[] COUNTRIES = {"FR", "DE", "ES", "IT", "NL", "AT", "SE", "CZ", "PL", "PT", "UK", "NO", "CH", "GB", "US", "AU", "JP"};
   private static final String[] ORGANIZATIONAL_UNITS = {"IT", "HR", "Finance", "Marketing", "Sales", "R&D", "Operations", "Legal", "Customer Service"};
   private static final String[] STATES = {"Paris", "Berlin", "Madrid", "Rome", "Amsterdam", "Vienna", "Stockholm", "Prague", "Warsaw", "Lisbon"};
   private static final String[] ADDRESSES = {
         "Rue de Rivoli 123",
         "Unter den Linden 45",
         "Calle de Alcalá 78",
         "Via del Corso 56",
         "Damrak 89",
         "Kärntner Straße 34",
         "Drottninggatan 67",
         "Václavské náměstí 12",
         "Nowy Świat 90",
         "Avenida da Liberdade 23",
         "Champs-Élysées 7",
         "Friedrichstraße 18",
         "Gran Vía 56",
         "Via Veneto 39",
         "Prinsengracht 101",
         "Stephansplatz 22",
         "Kungsgatan 45",
         "Karlova 8",
         "Krakowskie Przedmieście 33",
         "Rua Augusta 15",
         "Passeig de Gràcia 72",
         "Piazza Navona 9",
         "Rokin 50",
         "Graben 28",
         "Sveavägen 61",
         "Národní 14",
         "Aleje Jerozolimskie 55",
         "Rossio 31"
   };


   private final Random random;

   public RandomDataGenerator() {
      this.random = new Random();
   }

   public String generateAddress() {
      return ADDRESSES[random.nextInt(ADDRESSES.length)];
   }

   public String generateStates() {
      return STATES[random.nextInt(STATES.length)];
   }

   public String generateCompanyName() {
      String prefix = COMPANY_PREFIXES[random.nextInt(COMPANY_PREFIXES.length)];
      String suffix = COMPANY_SUFFIXES[random.nextInt(COMPANY_SUFFIXES.length)];
      return prefix + " " + suffix;
   }

   public String generateCity() {
      return CITIES[random.nextInt(CITIES.length)];
   }

   public String generateCountry() {
      return COUNTRIES[random.nextInt(COUNTRIES.length)];
   }

   public String generateOrganizationalUnit() {
      String[] units = {"IT", "HR", "Finance", "Marketing", "Sales", "R&D", "Operations", "Legal", "Customer Service"};
      return units[random.nextInt(units.length)];
   }

   public String generateState() {
      String[] states = {"Île-de-France", "Bavaria", "Catalonia", "Lazio", "North Holland", "Vienna", "Stockholm County", "Central Bohemia", "Masovia", "Lisbon District"};
      return states[random.nextInt(states.length)];
   }

   public String generateDomainName() {
      String[] domains = {"it", "no", "fr", "de", "es", "at", "se", "cz", "pl", "pt"};
      String companyName = generateCompanyName();
      return companyName.toLowerCase().replace(" ", "") + "." + domains[random.nextInt(domains.length)];
   }

   public String generateEmail() {
      String[] domains = {"it", "no", "fr", "de", "es", "at", "se", "cz", "pl", "pt"};
      String companyName = generateCompanyName();
      return generateOrganizationalUnit().toLowerCase().replace(" ", ".") + "@" + companyName.toLowerCase().replace(" ", "") + "." + domains[random.nextInt(domains.length)];
   }

   public static void main(String[] args) {
      RandomDataGenerator generator = new RandomDataGenerator();
      for (int i = 0; i < 10; i++) {
         System.out.println(generator.generateDomainName());
      }


   }


}