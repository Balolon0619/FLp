import 'dart:convert';
import 'package:http/http.dart' as http;
import 'user_model.dart';

class ApiService {
  static const String baseUrl = "http://localhost:5000";
  static String? authToken; // Store JWT token

  // User Registration
  static Future<bool> registerUser(String name, String email, String password) async {
    final response = await http.post(
      Uri.parse("$baseUrl/register"),
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({"name": name, "email": email, "password": password}),
    );

    print("Response Status: ${response.statusCode}");
    print("Response Body: ${response.body}");

    if (response.statusCode == 201) {
      return true;  // Registration successful
    } else {
      try {
        final Map<String, dynamic> responseData = jsonDecode(response.body);
        print("Error: ${responseData['message']}");
      } catch (e) {
        print("Error parsing response: $e");
      }
      return false; // Registration failed
    }
  }

  // User Login
  static Future<bool> loginUser(String email, String password) async {
    final response = await http.post(
      Uri.parse("$baseUrl/login"),
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({"email": email, "password": password}),
    );

    if (response.statusCode == 200) {
      try {
        final jsonResponse = json.decode(response.body);
        authToken = jsonResponse['token']; // Store token
        print("Login Successful, Token: $authToken");
        return true;
      } catch (e) {
        print("Error decoding login response: $e");
      }
    } else {
      print("Login failed with status: ${response.statusCode}");
    }
    return false;
  }

  // Fetch Users (Requires Authentication)
  static Future<List<User>> getUsers() async {
    final response = await http.get(
      Uri.parse("$baseUrl/users"),
      headers: {"Authorization": "Bearer $authToken"},
    );

    if (response.statusCode == 200) {
      try {
        List jsonResponse = json.decode(response.body);
        return jsonResponse.map((data) => User.fromJson(data)).toList();
      } catch (e) {
        print("Error decoding user list: $e");
      }
    } else {
      print("Failed to load users, status: ${response.statusCode}");
    }
    throw Exception("Failed to load users");
  }

  // Add User (Requires Authentication)
  static Future<bool> addUser(String name, String email) async {
    final response = await http.post(
      Uri.parse("$baseUrl/users"),
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer $authToken",
      },
      body: jsonEncode({"name": name, "email": email}),
    );

    if (response.statusCode == 201) {
      return true;
    } else {
      print("Failed to add user, status: ${response.statusCode}");
      return false;
    }
  }

  // Update User (Requires Authentication)
  static Future<bool> updateUser(int id, String name, String email) async {
    final response = await http.put(
      Uri.parse("$baseUrl/users/$id"),
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer $authToken",
      },
      body: jsonEncode({"name": name, "email": email}),
    );

    if (response.statusCode == 200) {
      return true;
    } else {
      print("Failed to update user, status: ${response.statusCode}");
      return false;
    }
  }

  // Delete User (Requires Authentication)
  static Future<bool> deleteUser(int id) async {
    final response = await http.delete(
      Uri.parse("$baseUrl/users/$id"),
      headers: {"Authorization": "Bearer $authToken"},
    );

    if (response.statusCode == 200) {
      return true;
    } else {
      print("Failed to delete user, status: ${response.statusCode}");
      return false;
    }
  }
}
